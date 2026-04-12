CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    state TEXT NOT NULL DEFAULT 'Creating',
    config TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
