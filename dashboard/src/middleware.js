import withAuth from "next-auth/middleware";

export default withAuth({
  pages: {
    signIn: "/login",
  },
});

export const config = {
  // Protect every page except the sign-in page, the NextAuth API routes
  // (which handle the OAuth handshake itself), and static assets.
  matcher: ["/((?!api|login|_next/static|_next/image|favicon.ico).*)"],
};
