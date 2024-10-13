import passport from "passport"
import { Strategy as GoogleStrategy, Profile } from "passport-google-oauth20";
import { generateToken } from "./auth.service";
import { prisma } from "@/db";
import { User } from "@prisma/client";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: '/auth/google/callback',
    },
    async (accessToken: string, _refreshToken: string, profile: Profile, done) => {
      try {
        const existingUser = await prisma.user.findUnique({ where: { googleId: profile.id } });

        if (existingUser) return done(null, existingUser);

        const user: User = await prisma.user.create({
          data: {
            email: profile.emails![0].value,
            googleId: profile.id,
            method: 'GOOGLE',
            name: profile.displayName,
          },
        });

        done(null, user);
      } catch (err) {
        done(err, false);
      }
    }
  )
);
