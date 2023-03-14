import re

import psycopg2
import uvicorn
from fastapi import FastAPI, HTTPException

app = FastAPI()


def check_if_database_exists():

    # Establish a connection to the PostgreSQL server
    try:
        connection = psycopg2.connect(
            host="api-db",
            user="postgres",
            password="postgres",
            database="sql_injection_detection",
        )

    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database connection error: {e}")

    return connection


def get_connection():
    return check_if_database_exists()


# Create a function to get all rows from the database table
def get_all_regular_expressions():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM regular_expressions ORDER BY id")
        rows = cur.fetchall()
        rows_dict = []
        for row in rows:
            row_dict = {"id": row[0], "description": row[1]}
            rows_dict.append(row_dict)
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cur.close()
        conn.close()
    return rows_dict


# Create a function to get a single row from the database table by id
def get_regular_expression_by_id(regular_expression_id: int):
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM regular_expressions WHERE id = %s ORDER BY id",
            [regular_expression_id],
        )
        row = cur.fetchone()
        row = {"id": row[0], "description": row[1]}
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cur.close()
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Regular expression not found")
    return row


# Create a function to create a new row in the database table
def create_regular_expression(regular_expression):
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO regular_expressions (description) VALUES (%s) RETURNING id",
            [regular_expression],
        )
        regular_expression_id = cur.fetchone()[0]
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cur.close()
        conn.close()
    return regular_expression_id


# Create a function to update an existing row in the database table
def update_regular_expression(regular_expression_id, regular_expression):
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE regular_expressions SET description = %s WHERE id = %s",
            [regular_expression, regular_expression_id],
        )
        conn.commit()
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cur.close()
        conn.close()


# Create a function to delete a row from the database table by id
def delete_regular_expression(regular_expression_id):
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM regular_expressions WHERE id = %s", [regular_expression_id]
        )
        conn.commit()
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cur.close()
        conn.close()


# Define endpoints for the web API
@app.get("/regular_expressions")
async def get_regular_expressions():
    return get_all_regular_expressions()


@app.get("/regular_expressions/{regular_expression_id}")
async def get_regular_expression(regular_expression_id: int):
    row = get_regular_expression_by_id(regular_expression_id)
    return row


@app.post("/regular_expressions")
async def create_new_regular_expression(regular_expression: str):
    regular_expression_id = create_regular_expression(regular_expression)
    return {"id": regular_expression_id}


@app.put("/regular_expressions/{regular_expression_id}")
async def update_existing_regular_expression(
    regular_expression_id: int, regular_expression: str
):
    get_regular_expression_by_id(regular_expression_id)
    update_regular_expression(regular_expression_id, regular_expression)
    return {"message": "Regular_expression updated successfully"}


@app.delete("/regular_expressions/{regular_expression_id}")
async def delete_existing_regular_expression(regular_expression_id: int):
    get_regular_expression_by_id(regular_expression_id)
    delete_regular_expression(regular_expression_id)
    return {"message": "Regular expression deleted successfully"}


@app.get("/sql_injection_detection")
def sql_injection_detection(string: str):

    regular_expressions = get_all_regular_expressions()

    for expression in regular_expressions:
        regex = re.search(expression.get("description"), string, re.IGNORECASE)

        if regex:
            return {"message": "sql_injection_detected"}

    return {"message": "sql_injection_not_detected"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
