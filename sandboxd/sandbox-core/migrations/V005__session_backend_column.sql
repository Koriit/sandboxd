ALTER TABLE sessions ADD COLUMN backend TEXT NOT NULL DEFAULT 'lima'
  CHECK (backend IN ('lima', 'container'));
