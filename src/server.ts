import express, { Application } from 'express';
import bodyParser from 'body-parser';
import * as grpc from '@grpc/grpc-js';
import { AppDataSource } from '@config/data.source';
import indexRouter from './v1/route';
import DotenvConfig from '@config/dotenv.config';
import { errorHandler, routeNotFound } from '@middlewares/error.middleware';
import UserServiceImpl from '@grpc/server/user.server';
import { Protos } from './grpc';

export default class Server {
  public app: Application;
  private grpcServer: grpc.Server;
  private grpcPort: number;

  constructor() {
    this.app = express();
    this.grpcServer = new grpc.Server();
    this.grpcPort = DotenvConfig.grpcPort;
    console.log('Registering middlewares...');
    this.initializeMiddlewares();
    console.log('Registering routes...');
    this.routes();
    console.log('Registering error handlers...');
    this.handleErrors();
    console.log('Connecting to database...');
    this.connectDatabase();
    console.log('Setting up gRPC server...');
    this.setupGrpcServer();
    this.setupGracefulShutdown();
  }

  initializeMiddlewares() {
    this.app.use(bodyParser.urlencoded({ extended: true }));
    this.app.use(express.json());
    // this.app.use(cors(corsOptions));
    // this.app.options(cors(corsOptions));
  }

  handleErrors() {
    this.app.use(errorHandler);
    this.app.use(routeNotFound);
  }

  routes() {
    this.app.get('/v1/api', (req, res) => {
      res.send({
        success: true,
        message: 'Server initialized and ready for action!',
      });
    });
    this.app.use('/v1/api', indexRouter);
  }

  async connectDatabase() {
    try {
      await AppDataSource.initialize();
      console.log('Database connection established successfully!');
    } catch (error) {
      console.error('Error connecting to the database:', error);
      process.exit(1);
    }
  }

  setupGrpcServer() {
    try {
      const userService = new UserServiceImpl();

      // Add user service to gRPC server
      this.grpcServer.addService(Protos.user.UserService.service, {
        getUser: userService.getUser,
        getUserEmail: userService.getUserEmail,
        signin: userService.signin,
        signup: userService.signup,
        verifyOTP: userService.verifyOTP,
        resendOTP: userService.resendOTP,
        // listUsers: userService.listUsers,
      });

      console.log('gRPC services registered successfully');
    } catch (error) {
      console.error('Error setting up gRPC server:', error);
      throw error;
    }
  }

  startGrpcServer() {
    return new Promise<void>((resolve, reject) => {
      this.grpcServer.bindAsync(
        `0.0.0.0:${this.grpcPort}`,
        grpc.ServerCredentials.createInsecure(),
        (err, port) => {
          if (err) {
            console.error('Failed to start gRPC server:', err);
            reject(err);
            return;
          }
          console.log(`🚀 gRPC server running on port ${port}`);
          resolve();
        }
      );
    });
  }

  setupGracefulShutdown() {
    const gracefulShutdown = async (signal: string) => {
      console.log(`\nReceived ${signal}, cleaning up...`);

      this.grpcServer.tryShutdown(async (err) => {
        if (err) {
          console.error('Error shutting down gRPC server:', err);
        } else {
          console.log('gRPC server closed gracefully');
        }

        // Closing database connection
        try {
          await AppDataSource.destroy();
          console.log('Database connection closed');
        } catch (error) {
          console.error('Error closing database:', error);
        }

        process.exit(0);
      });

      // Force close after 10 seconds
      setTimeout(() => {
        console.error(
          'Could not close connections in time, forcefully shutting down'
        );
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    process.on('uncaughtException', (error) => {
      console.error('Uncaught Exception:', error);
      gracefulShutdown('UNCAUGHT_EXCEPTION');
    });

    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
      gracefulShutdown('UNHANDLED_REJECTION');
    });
  }

  async start(port: number) {
    try {
      this.app.listen(port, () => {
        console.log(`Server initialized and ready for action! 🤖`);
        console.log('     /\\_/\\');
        console.log('    / o o \\');
        console.log('   (   "   )');
        console.log('    \\~(*)~/');
        console.log('     /___\\');
        console.log('Welcome to the enchanted forest of code!');

        this.startGrpcServer();

        console.log('\n✅ All servers started successfully!');
        console.log(`📡 HTTP API: http://localhost:${port}`);
        console.log(`🔌 gRPC Service: localhost:${this.grpcPort}`);
      });
    } catch (error) {
      console.error('Failed to start servers:', error);
      process.exit(1);
    }
  }
}
