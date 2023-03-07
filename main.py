import re

from fastapi import FastAPI

app = FastAPI()

regexes_to_test = [
    r"(?:')|(?:--)|(?:#)",
    """
    '(single quote) used to terminate a SQL statement and inject malicious code
    -- used to comment out the rest of a SQL statement and inject malicious code
    # used to comment out the rest of a SQL statement and inject malicious code
    """
    r"\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|SELECT|UNION( +ALL){0,1}|UPDATE)\b",
    """
    This regex pattern matches common SQL keywords such as ALTER, CREATE, DELETE, DROP, EXEC, INSERT, SELECT, UNION, and UPDATE.
    """,
    r"\b\d+('|;\s*|--\s*|#\s*)",
    """
    This regex pattern matches numeric values followed by a single quote, semicolon, or comment characters used in SQL injection attacks.
    """,
    r"(?i)\b(TRUE|FALSE|NULL|NOT)\b|[-+]*(\d|\.\d+|0x[0-9a-f]+)",
    """
    This regex pattern matches boolean values and numeric values used in SQL injection attacks.
    """,
    r"(?i)(?:(?:\d+[xX][0-9a-fA-F]+)|(?:'[\w\s]*')|(?:\"[\w\s]*\")|(?:;[^\w;]*?\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE)\b[^\w;]*?(?:FROM|\bINTO\b)))",
    """
    This regex pattern matches tautologies, which are statements that always evaluate to true, and commonly used in SQL injection attacks. Examples of tautologies include 1=1, ' OR 1=1 --, 1' OR '1'='1, and ''''; SELECT * FROM users--.
    """,
    r"(?i)\bUNION\s+ALL\s+SELECT\b",
    """
    This regex pattern matches the UNION ALL SELECT statement, which is commonly used in SQL injection attacks to retrieve data from other tables.
    """,
    r"(?i)\b(?:RAISERROR|THROW)\b",
    """
    This regex pattern matches error-inducing SQL statements such as RAISERROR and THROW, which are commonly used in SQL injection attacks to force the database server to reveal sensitive information.
    """,
]


@app.get("/sql_injection_detection")
def sql_injection_detection(string: str):
    for expression in regexes_to_test:
        regex = re.search(expression, string, re.IGNORECASE)

        if regex:
            return {"message": "sql_injection_detected"}

    return {"message": "sql_injection_not_detected"}
