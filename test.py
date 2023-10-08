import psycopg2
import dotenv

# Laad de databasegegevens uit het .env-bestand
dotenv.load_dotenv('./storage/db.key')

DBUSERNAME = dotenv.get_key('./storage/db.key', 'username')
DBPASSWORD = dotenv.get_key('./storage/db.key', 'password')
DBHOSTNAME = dotenv.get_key('./storage/db.key', 'host')
DBHOSTPORT = dotenv.get_key('./storage/db.key', 'port')

# Verbinding maken met de database en SQL-query uitvoeren
con = psycopg2.connect(
    dbname='main',
    user=DBUSERNAME,
    password=DBPASSWORD,
    host=DBHOSTNAME,
    port=DBHOSTPORT
)

try:
    with con.cursor() as cur:
        # Voeg gegevens toe aan de "auth" -tabel
        cur.execute('''INSERT INTO "public"."auth" ("id", "mail", "pass", "profilepicture", "userid", "username")
                       VALUES ('1', 'mail@bijsvenlol.com', '1234', 'test', 'test', 'Sven');''')
        con.commit()
        print("Gegevens zijn succesvol toegevoegd aan de tabel 'auth'.")

    with con.cursor() as cur:
        cur.execute('''SELECT * FROM "public"."auth";''')
        records = cur.fetchall()
        print("Alle gegevens in de tabel 'auth':")
        for record in records:
            print(record)
except psycopg2.Error as e:
    print(f"Fout bij het uitvoeren van SQL-query: {e}")
finally:
    con.close()
