import { Strategy as GoogleStrategy, Profile } from "passport-google-oauth20";
import { Strategy as JwtStrategy, ExtractJwt, VerifiedCallback } from "passport-jwt";
import { prisma } from "@/db";
import { Method, User } from "@prisma/client";
import { Request } from "express";

const cookieExtractor = (req: Request): string | null => {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['access_token'];
  }
  return token;
};

const googleStrategy =
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: '/auth/google/callback',
    },
    async (_access_token: string, _refreshToken: string, profile: Profile, done) => {
      try {
        const existingUser = await prisma.user.findUnique({ where: { googleId: profile.id } });

        if (existingUser)
          return done(null, existingUser);

        const email = profile.emails?.[0].value;
        if (!email)
          return done(new Error('No email associated with this account'), false);

        const user: User = await prisma.user.create({
          data: {
            email: email,
            googleId: profile.id,
            method: Method.GOOGLE,
            name: profile.displayName || email.split('@')[0],
          },
        });

        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  );

const jwtStrategy = new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
    secretOrKey: process.env.JWT_SECRET as string,
  },
  async (payload: { id: string, email: string }, done: VerifiedCallback) => {
    try {
      const user = await prisma.user.findUnique({ where: { id: payload.id } });
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    } catch (error) {
      return done(error as Error, false);
    }
  }
)

export {
  googleStrategy,
  jwtStrategy
};
