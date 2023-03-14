CREATE TABLE IF NOT EXISTS regular_expressions (
    id SERIAL PRIMARY KEY,
    description VARCHAR(255) NOT NULL
);
INSERT INTO "regular_expressions" ("id", "description") VALUES (8, '(\%20and|\+and|&&|\&\&)');
INSERT INTO "regular_expressions" ("id", "description") VALUES (4, '(\W)(and|or)\s*\d+\s*(=|\>\=|\<\=|\>\\<|\<|\>)');
INSERT INTO "regular_expressions" ("id", "description") VALUES (7, '([\s\(\)])(exec|execute)([\s\(\)])');
INSERT INTO "regular_expressions" ("id", "description") VALUES (1, '(\%27)|(\'')|(--[^\r\n]*)|(;%00)');
INSERT INTO "regular_expressions" ("id", "description") VALUES (2, '((\%3D)|(=))[^\n]*((\%27)|(\'')|(\-\-)|(\%3B)|(;))');
INSERT INTO "regular_expressions" ("id", "description") VALUES (6, '([\s\(\)])(select|drop|insert|delete|update|create|alter)([\s\(\)])');
INSERT INTO "regular_expressions" ("id", "description") VALUES (3, '((\%27)|(\''))((\%6F)|o|(\%4F))((\%72)|r|(\%52))');
INSERT INTO "regular_expressions" ("id", "description") VALUES (5, '((\%27)|(\''))UNION');