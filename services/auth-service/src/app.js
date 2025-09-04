import express from 'express';
import userRoutes from './routes/user.routes.js';
import authRoutes from './routes/auth.routes.js';
import otpRoutes from './routes/otp.routes.js'
import githubOauthRoutes from './routes/gitHubOauth.routes.js';
import morgan from 'morgan';
import passport from 'passport';
import cors from 'cors';

const app = express();

app.use(passport.initialize());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));


app.use(cors({
  origin: '*',
  credentials: true
}));

app.use('/users', userRoutes);
app.use('/auth', authRoutes);
app.use('/otp', otpRoutes);
app.use('/api/auth', githubOauthRoutes);


export default app;