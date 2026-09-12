import { NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { getDb } from "@/lib/mongodb";
import { fetchAccessibleRepoNames } from "@/lib/github";

export async function GET() {
  const session = await getServerSession(authOptions);

  if (!session?.accessToken) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  let accessibleRepos;
  try {
    accessibleRepos = await fetchAccessibleRepoNames(session.accessToken);
  } catch (err) {
    return NextResponse.json(
      { error: "Failed to verify GitHub repository access" },
      { status: 502 }
    );
  }

  const db = await getDb();
  const scans = await db
    .collection("scans")
    .find(
      { repo: { $in: Array.from(accessibleRepos) } },
      { projection: { _id: 0 } }
    )
    .sort({ timestamp: -1 })
    .toArray();

  return NextResponse.json({
    last_updated: new Date().toISOString(),
    total_scans: scans.length,
    scans,
  });
}
