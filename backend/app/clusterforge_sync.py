"""ClusterForge beheert een deel van het dashboard: een groep per cluster en een tegel per cluster en per node.

Aan te zetten in het mini dashboard van een ClusterForge-tegel (overzicht, zonder `cluster`): die tegel is dan de
bron. Elke 5 minuten (en met "nu synchroniseren") vraagt de worker de clusters en nodes aan ClusterForge en zet het
dashboard gelijk:

- per cluster een groep op de gekozen pagina (standaard een eigen pagina "ClusterForge"), nodes zonder cluster in
  "Losse nodes";
- in die groep een tegel voor het cluster (check rood zolang het niet in orde is) en een tegel per node (check rood
  als de node offline of down is, behalve in onderhoud);
- nieuw in ClusterForge = nieuwe tegel, hernoemd of naar een ander cluster = bijgewerkt, weg in ClusterForge = weg
  hier.

Alleen tegels met `cf_beheer` in de instellingen zijn van ClusterForge; met de hand gemaakte tegels (ook in die
groepen) blijven altijd staan. Van een beheerde tegel neemt ClusterForge de naam, de link, de omschrijving en de groep;
icoon, plaats, check, notities en onderhoud blijven wat je zelf zet.

Veiligheid: lukt het ophalen niet, dan verandert er niets. Zou één ronde meer dan de helft van de beheerde tegels
(en meer dan 3) weghalen, dan haalt de worker niets weg en meldt hij het: "nu synchroniseren" doet het dan wel. Kent
ClusterForge /nodes nog niet, dan komen er alleen groepen en clustertegels, en blijven bestaande nodetegels staan.
Elke ronde met wijzigingen is een revisie (terug te zetten zoals elke wijziging van de layout).
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import ensure_state
from .deps import notify
from .integrations import IntegrationError, build
from .integrations.clusterforge import ClusterForge
from .layout import record_revision
from .models import Group, Page, Service

log = logging.getLogger("homepage.clusterforge")

STATE_KEY = "clusterforge_beheer"
EVERY = 300
MARK = "cf_beheer"
LOOSE = "_los"
LOOSE_NAME = "Losse nodes"
PAGE_NAME = "ClusterForge"
CHECK = {"type": "api", "interval": 60}


def tile_base(src: Service, integ: ClusterForge) -> dict:
    """Hoe een nieuwe tegel aan ClusterForge hangt: dezelfde API als de bron, of dezelfde url en sleutels."""
    if src.api_id:
        return {"api_id": src.api_id, "config": {}, "secrets": None}
    config = {k: v for k, v in (src.config or {}).items() if k not in ("cluster", "soc", "node", MARK)}
    # De url van de API altijd in de instellingen: de url van de tegel zelf is de link naar ClusterForge.
    return {"api_id": None, "config": {**config, "url": integ.base}, "secrets": src.secrets}


def _desired(integ: ClusterForge, clusters: list[dict], nodes: list[dict] | None) -> tuple[dict, dict]:
    """(groepen {sleutel: naam}, tegels {merk: {...}}) zoals ClusterForge ze nu ziet."""
    groups: dict[str, str] = {}
    tiles: dict[str, dict] = {}
    for c in clusters:
        cid = str(c.get("id") or c.get("slug"))
        groups[cid] = str(c.get("name") or c.get("slug"))[:80]
        kind = " · ".join(x for x in (c.get("type"), c.get("environment")) if x)
        tiles[f"cluster:{cid}"] = {"group": cid, "name": str(c.get("name") or c.get("slug"))[:80],
                                   "url": integ.link(c.get("url")), "description": f"cluster{' · ' + kind if kind else ''}",
                                   "config": {"cluster": str(c.get("slug") or cid)}, "icon": "mdi-server-network",
                                   "order": (0, "")}
    for n in nodes or []:
        cid = str(n.get("cluster_id") or "")
        if cid and cid not in groups:
            continue  # cluster niet zichtbaar met dit token
        g = cid or LOOSE
        if g == LOOSE:
            groups[LOOSE] = LOOSE_NAME
        desc = " · ".join(str(x) for x in (n.get("role"), n.get("primary_ip")) if x)
        tiles[f"node:{n['id']}"] = {"group": g, "name": str(n.get("hostname") or n["id"])[:80],
                                    "url": integ.link(n.get("url")), "description": desc[:255] or None,
                                    "config": {"node": str(n["id"])}, "icon": "mdi-server",
                                    "order": (1, str(n.get("hostname") or "").lower())}
    return groups, tiles


async def _page(db: AsyncSession, value: dict) -> Page:
    page = await db.get(Page, value.get("page_id")) if value.get("page_id") else None
    if page is None:
        pos = (await db.execute(select(func.coalesce(func.max(Page.position), -1)))).scalar_one() + 1
        page = Page(name=PAGE_NAME, icon="mdi-server-network", position=pos)
        db.add(page)
        await db.flush()
    return page


async def sync(db: AsyncSession, http, force: bool = False) -> dict:
    """Eén ronde. Geeft terug wat er veranderde (of waarom niet)."""
    st = await ensure_state(db, STATE_KEY, {})
    value = dict(st.value or {})
    sid = value.get("service_id")
    if not sid:
        return {"skipped": True}
    now = datetime.now(timezone.utc).isoformat()

    def done(result: dict) -> dict:
        st.value = {**value, "last": {"at": now, **result}}
        return result

    src = await db.get(Service, sid)
    if src is None or src.type != "clusterforge":
        return done({"error": "De ClusterForge-tegel van het beheer bestaat niet meer: kies een andere."})
    try:
        integ = build(src, http)
        if not isinstance(integ, ClusterForge):
            raise IntegrationError("Geen ClusterForge-integratie")
        clusters = await integ.clusters()
        nodes = await integ.nodes() if value.get("nodes", True) else []
    except IntegrationError as e:
        return done({"error": str(e)[:300]})

    groups_want, tiles_want = _desired(integ, clusters, nodes)
    page = await _page(db, value)
    value["page_id"] = page.id

    # Groepen: die van ClusterForge houden (naam en pagina komen van het beheer), ontbrekende maken.
    gmap: dict[str, int] = dict(value.get("groups") or {})
    groups: dict[str, Group] = {}
    for key, name in groups_want.items():
        g = await db.get(Group, gmap.get(key)) if gmap.get(key) else None
        if g is None:
            pos = (await db.execute(select(func.coalesce(func.max(Group.position), -1))
                                    .where(Group.page_id == page.id))).scalar_one() + 1
            g = Group(page_id=page.id, name=name, position=pos)
            db.add(g)
            await db.flush()
        else:
            if g.name != name:
                g.name = name
            if g.page_id != page.id:  # een andere pagina gekozen: de groepen verhuizen mee
                g.page_id = page.id
        groups[key] = g
        gmap[key] = g.id

    every = list((await db.execute(select(Service).where(Service.type == "clusterforge"))).scalars())
    managed = {str((s.config or {}).get(MARK)): s for s in every if (s.config or {}).get(MARK)}
    # Tegels die je al eerder per cluster of node maakte (tegels per cluster): die neemt het beheer over in plaats
    # van er een tweede naast te zetten. De bron zelf nooit.
    loose = {}
    for s in every:
        c = s.config or {}
        if c.get(MARK) or s.id == src.id or c.get("soc"):
            continue
        for k in ("cluster", "node"):
            if c.get(k):
                loose.setdefault((k, str(c[k]).strip().lower()), s)
    by_alias = {}
    for c in clusters:
        for a in (c.get("id"), c.get("slug"), c.get("name")):
            if a:
                by_alias[("cluster", str(a).lower())] = f"cluster:{c.get('id') or c.get('slug')}"
    for n in nodes or []:
        for a in (n.get("id"), n.get("hostname")):
            if a:
                by_alias[("node", str(a).lower())] = f"node:{n['id']}"
    for key, s in loose.items():
        mark = by_alias.get(key)
        if mark and mark not in managed:
            managed[mark] = s
    base = tile_base(src, integ)
    added = changed = removed = 0
    for mark, t in sorted(tiles_want.items(), key=lambda kv: (kv[1]["group"], kv[1]["order"])):
        g = groups[t["group"]]
        s = managed.get(mark)
        config = {**base["config"], **t["config"], MARK: mark}
        if s is None:
            pos = (await db.execute(select(func.coalesce(func.max(Service.position), -1))
                                    .where(Service.group_id == g.id))).scalar_one() + 1
            db.add(Service(group_id=g.id, name=t["name"], url=(t["url"] or "")[:500] or None, description=t["description"],
                           icon=t["icon"], position=pos, type="clusterforge", config=config, secrets=base["secrets"],
                           api_id=base["api_id"], parent_id=src.id, check=dict(CHECK)))
            added += 1
            continue
        before = (s.name, s.url, s.description, s.group_id, s.config, s.api_id)
        s.name, s.url, s.description, s.group_id = t["name"], (t["url"] or "")[:500] or None, t["description"], g.id
        # Eigen instellingen op de tegel (bv. zabbix) houden; de sleutels van ClusterForge gelijkzetten.
        s.config = {**{k: v for k, v in (s.config or {}).items() if k not in ("cluster", "node")}, **config}
        s.api_id = base["api_id"]
        if not base["api_id"]:
            s.secrets = base["secrets"]
        if before != (s.name, s.url, s.description, s.group_id, s.config, s.api_id):
            changed += 1

    gone = [s for mark, s in managed.items() if mark not in tiles_want
            and not (nodes is None and mark.startswith("node:"))]
    held = 0
    if gone and not force and len(gone) > 3 and len(gone) * 2 > len(managed):
        held = len(gone)  # veiligheidsrem: niets weghalen
        gone = []
    for s in gone:
        await db.delete(s)
        removed += 1
    await db.flush()

    # Groepen van ClusterForge die niet meer nodig zijn: weg als er niets meer in staat (met de hand gemaakte tegels
    # houden de groep).
    for key, gid in list(gmap.items()):
        if key in groups_want:
            continue
        g = await db.get(Group, gid)
        left = 0 if g is None else (await db.execute(select(func.count(Service.id))
                                                     .where(Service.group_id == gid))).scalar_one()
        if g is not None and not left:
            await db.delete(g)
        if g is None or not left:
            gmap.pop(key)
    value["groups"] = gmap

    result = {"added": added, "changed": changed, "removed": removed, "held": held, "clusters": len(clusters),
              "nodes": None if nodes is None else len(nodes), "error": None}
    if added or changed or removed:
        summary = f"ClusterForge: {added} tegels nieuw, {changed} bijgewerkt, {removed} weg"
        await record_revision(db, None, summary)
        notify(db, summary, level="info", source="clusterforge", push=False)
    if held:
        notify(db, f"ClusterForge: {held} beheerde tegels zouden weg moeten, niets weggehaald",
               "Meer dan de helft van de tegels van ClusterForge verdween in één keer (token ingetrokken of beperkt?). "
               "Klopt het, kies dan in het mini dashboard van de ClusterForge-tegel 'nu synchroniseren'.",
               level="warn", source="clusterforge", key="clusterforge-rem")
    return done(result)


async def run(db: AsyncSession, http) -> dict:
    """Voor de worker: elke 5 minuten, alleen als het beheer aan staat."""
    try:
        return await sync(db, http)
    except Exception:
        log.exception("ClusterForge-beheer mislukt")
        raise
