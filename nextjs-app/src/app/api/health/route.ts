import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json({
    status: "HEALTHY",
    timestamp: new Date().toISOString(),
  });
}
