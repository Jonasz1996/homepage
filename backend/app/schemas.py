from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PageIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    icon: str | None = Field(default=None, max_length=255)


class GroupIn(BaseModel):
    page_id: int
    name: str = Field(min_length=1, max_length=80)
    icon: str | None = Field(default=None, max_length=255)
    collapsed: bool = False


class ServiceIn(BaseModel):
    group_id: int
    name: str = Field(min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=500)
    icon: str | None = Field(default=None, max_length=500)
    type: str = Field(default="link", max_length=40)
    check: dict = Field(default_factory=dict)
    config: dict = Field(default_factory=dict)
    # None = ongewijzigd laten. Een sleutel met lege waarde wordt verwijderd.
    secrets: dict[str, str | None] | None = None
    parent_id: int | None = None
    notes: str | None = Field(default=None, max_length=20000)

    @field_validator("url")
    @classmethod
    def _url_scheme(cls, v: str | None) -> str | None:
        if v and not v.lower().startswith(("http://", "https://")):
            raise ValueError("URL moet met http:// of https:// beginnen")
        return v or None


class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    group_id: int
    name: str
    description: str | None
    url: str | None
    icon: str | None
    position: int
    type: str
    check: dict
    config: dict
    parent_id: int | None = None
    maintenance_until: datetime | None = None
    notes: str | None = None
    secret_keys: list[str] = []


class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    page_id: int
    name: str
    icon: str | None
    position: int
    collapsed: bool
    services: list[ServiceOut]


class PageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    icon: str | None
    position: int
    groups: list[GroupOut]


class OrderIn(BaseModel):
    """Nieuwe volgorde na slepen. Groepen en services kunnen zo ook van ouder wisselen."""

    pages: list[int] | None = None
    groups: dict[int, list[int]] | None = None
    services: dict[int, list[int]] | None = None


class ImportIn(BaseModel):
    yaml: str = Field(max_length=2_000_000)
    page_id: int | None = None
    page_name: str | None = Field(default=None, max_length=80)
