CREATE TABLE IF NOT EXISTS regular_expressions (
    id SERIAL PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    captured_injections INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS detected_injections (
    id SERIAL PRIMARY KEY,
    description TEXT UNIQUE NOT NULL,
    detected_times INTEGER NOT NULL DEFAULT 0
);
INSERT INTO "regular_expressions" ("id", "description", "captured_injections") VALUES (8, '(\%20and|\+and|&&|\&\&)', 0);
INSERT INTO "regular_expressions" ("id", "description", "captured_injections") VALUES (4, '(\W)(and|or)\s*\d+\s*(=|\>\=|\<\=|\>\\<|\<|\>)', 0);
INSERT INTO "regular_expressions" ("id", "description", "captured_injections") VALUES (7, '([\s\(\)])(exec|execute)([\s\(\)])', 0);
INSERT INTO "regular_expressions" ("id", "description", "captured_injections") VALUES (1, '(\%27)|(\'')|(--[^\r\n]*)|(;%00)', 0);
INSERT INTO "regular_expressions" ("id", "description", "captured_injections") VALUES (2, '((\%3D)|(=))[^\n]*((\%27)|(\'')|(\-\-)|(\%3B)|(;))', 0);
INSERT INTO "regular_expressions" ("id", "description", "captured_injections") VALUES (6, '([\s\(\)])(select|drop|insert|delete|update|create|alter)([\s\(\)])', 0);
INSERT INTO "regular_expressions" ("id", "description", "captured_injections") VALUES (3, '((\%27)|(\''))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', 0);
INSERT INTO "regular_expressions" ("id", "description", "captured_injections") VALUES (5, '((\%27)|(\''))UNION', 0);
