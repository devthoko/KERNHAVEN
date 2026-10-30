-- Built-in catalog and switchable sources (ADR-0034).

-- 1 for the catalog that ships inside Kernhaven ("Kernhaven Essentials"):
-- no trust key, no URL, updated by Kernhaven itself.
ALTER TABLE catalog_sources ADD COLUMN builtin INTEGER NOT NULL DEFAULT 0 CHECK (builtin IN (0, 1));
-- A disabled source keeps its catalog but offers no apps and no updates.
ALTER TABLE catalog_sources ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1));
CREATE UNIQUE INDEX catalog_sources_one_builtin ON catalog_sources (builtin) WHERE builtin = 1;
