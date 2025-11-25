Jeżeli macie problemy z uruchomieniem backendu, proszę zastosować polecenie: npx prisma generate

Zawartość pliku .env:

DATABASE_URL='postgresql://neondb_owner:npg_y8BdQOHasp1i@ep-winter-paper-agab43m0-pooler.c-2.eu-central-1.aws.neon.tech/neondb?sslmode=require'
JWT_SECRET=secret

# Google Gemini API Key for AI chat
GEMINI_API_KEY=secret_key_here

Użyjcie albo podanego URL do bazy danych albo skopiujcie ze swojej bazy danych PostgrSQL.

Klucz do AI można uzyskać z:
https://aistudio.google.com/
