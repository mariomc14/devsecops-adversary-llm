def get_transaction_by_origin(id_origin):
        query = f"SELECT * FROM transactions WHERE id >= {id_origin};"
        conn.execute(query)
        return conn.fetchall()
    