import csv
import re
from time import perf_counter

import matplotlib.pyplot as plt
import numpy as np
import psycopg2
import uvicorn
from fastapi import FastAPI, HTTPException

app = FastAPI()

regexes_to_test = [
    r"(\%27)|(\')|(--[^\r\n]*)|(;%00)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"(\W)(and|or)\s*\d+\s*(=|\>\=|\<\=|\>\\<|\<|\>)",
    r"((\%27)|(\'))UNION",
    r"([\s\(\)])(select|drop|insert|delete|update|create|alter)([\s\(\)])",
    r"([\s\(\)])(exec|execute)([\s\(\)])",
    r"(\%20and|\+and|&&|\&\&)",
]


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
        cur.execute("SELECT * FROM regular_expressions")
        rows = cur.fetchall()
        rows_dict = []
        for row in rows:
            row_dict = {
                "id": row[0],
                "description": row[1],
                "captured_injections": row[2],
            }
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
            "SELECT * FROM regular_expressions WHERE id = %s", [regular_expression_id]
        )
        row = cur.fetchone()
        row = {
            "id": row[0],
            "description": row[1],
            "captured_injections": row[2],
        }
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


@app.post("/generate_graph")
def generate_graph():
    # Load the matrix from file
    matrix = np.loadtxt("data/output_without_crud.txt")

    # Generate random data
    data = matrix.astype(float).transpose()

    print(data)

    # Calculate standard deviation
    std = np.std(data, axis=1)

    # Plot the graph
    plt.errorbar(range(1, 9), np.mean(data, axis=1), yerr=std, fmt="o", capsize=5)

    # Set the axis labels
    plt.xlabel("Regular Expression")
    plt.ylabel("time (ms)")

    # Set the title
    plt.title(
        f"Plot with 8 regular expressions, {len(data[0])} samples, and standard deviation"
    )

    # Show the plot
    plt.savefig("data/sample_plot_without_crud.png")

    plt.clf()

    # Load the matrix from file
    matrix = np.loadtxt("data/output_with_crud.txt")

    # Generate random data
    data = matrix.astype(float).transpose()

    print(data)

    # Calculate standard deviation
    std = np.std(data, axis=1)

    # Plot the graph
    plt.errorbar(range(1, 9), np.mean(data, axis=1), yerr=std, fmt="o", capsize=5)

    # Set the axis labels
    plt.xlabel("Regular Expression")
    plt.ylabel("time (ms)")

    # Set the title
    plt.title(
        f"Plot with 8 regular expressions, {len(data[0])} samples, and standard deviation"
    )

    # Show the plot
    plt.savefig("data/sample_plot_with_crud.png")

    return {"message": "graph_generated"}


@app.post("/generate_data/with_crud")
def generate_data():
    count = -1

    elapsed_time = [[] for _ in range(8)]
    try:
        conn = get_connection()
        cur = conn.cursor()

        with open("SQLiV3.csv") as csvfile:
            reader = csv.reader(csvfile)

            for row in reader:
                count = count + 1
                if count == 10000:
                    break
                print(count)

                regular_expressions = get_all_regular_expressions()
                count2 = -1
                for expression in regular_expressions:

                    start_time = perf_counter()
                    get_all_regular_expressions()

                    count2 = count2 + 1

                    regex = re.search(
                        expression.get("description"), row[0], re.IGNORECASE
                    )

                    end_time = perf_counter()
                    elapsed_time_ms = (end_time - start_time) * 1000
                    elapsed_time[count2].append(elapsed_time_ms)
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.commit()
        cur.close()
        conn.close()

    # elapsed_time = [sum(inner_list) / len(inner_list) for inner_list in elapsed_time]

    A = np.array(elapsed_time)
    A_inv = np.transpose(A)

    with open("data/output_with_crud.txt", "w") as f:
        # Loop over the data and write it to the file
        """for i in range(1, len(elapsed_time) + 1):
            if i != 1:
                f.write(" ")
            f.write("{}".format(i))
        f.write("\n")"""
        for i in A_inv:
            for j in i:
                f.write("{} ".format(j))
            f.write("\n")
    return {"message": "data_generated"}


@app.post("/generate_data/without_crud")
def generate_data():
    count = -1

    elapsed_time = [[] for _ in range(8)]
    try:
        conn = get_connection()
        cur = conn.cursor()

        with open("SQLiV3.csv") as csvfile:
            reader = csv.reader(csvfile)

            for row in reader:
                count = count + 1
                if count == 10000:
                    break
                print(count)

                regular_expressions = get_all_regular_expressions()
                count2 = -1
                for expression in regular_expressions:

                    start_time = perf_counter()

                    count2 = count2 + 1

                    regex = re.search(
                        expression.get("description"), row[0], re.IGNORECASE
                    )

                    end_time = perf_counter()
                    elapsed_time_ms = (end_time - start_time) * 1000
                    elapsed_time[count2].append(elapsed_time_ms)
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cur.close()
        conn.close()

    # elapsed_time = [sum(inner_list) / len(inner_list) for inner_list in elapsed_time]

    A = np.array(elapsed_time)
    A_inv = np.transpose(A)

    with open("data/output_without_crud.txt", "w") as f:
        # Loop over the data and write it to the file
        """for i in range(1, len(elapsed_time) + 1):
            if i != 1:
                f.write(" ")
            f.write("{}".format(i))
        f.write("\n")"""
        for i in A_inv:
            for j in i:
                f.write("{} ".format(j))
            f.write("\n")
    return {"message": "data_generated"}


@app.get("/sql_injection_detection")
def sql_injection_detection(string: str):

    for expression in regexes_to_test:
        regex = re.search(expression, string, re.IGNORECASE)

        if regex:
            return {"message": "sql_injection_detected"}

    return {"message": "sql_injection_not_detected"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="debug", reload=True)
