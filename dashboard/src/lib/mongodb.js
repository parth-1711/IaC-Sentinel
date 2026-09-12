import { MongoClient } from "mongodb";

const uri = process.env.MONGO_URI || "mongodb://localhost:27017";
const dbName = process.env.MONGO_DB_NAME || "iac_sentinel";

// Cache the connection on the global object so hot-reload in dev and
// serverless invocations don't each open a fresh connection.
let clientPromise = global._mongoClientPromise;

if (!clientPromise) {
  const client = new MongoClient(uri);
  clientPromise = client.connect();
  global._mongoClientPromise = clientPromise;
}

export async function getDb() {
  const client = await clientPromise;
  return client.db(dbName);
}
