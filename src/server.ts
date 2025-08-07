import express, { Application } from 'express';
import bodyParser from 'body-parser';
import { AppDataSource } from '@config/data.source';

export default class Server {
  public app: Application;

  constructor() {
    this.app = express();
    console.log('Registering middlewares...');
    // this.initializeMiddlewares();
    // console.log("Registering routes...");
    // this.routes();
    // console.log("Registering error handlers...");
    // this.handleErrors();
    console.log('Connecting to database...');
    this.connectDatabase();
  }

  initializeMiddlewares() {
    this.app.use(bodyParser.urlencoded({ extended: true }));
    this.app.use(express.json());
    // this.app.use(cors(corsOptions));
    // this.app.options(cors(corsOptions));
  }

  handleErrors() {
    // this.app.use(errorHandler);
    // this.app.use(routeNotFound);
  }

  routes() {
    this.app.get('/v1/api', (req, res) => {
      res.send({
        success: true,
        message: 'Server initialized and ready for action!',
      });
    });
    // this.app.use("/v1/api", indexRouter);
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

  start(port: number) {
    this.app.listen(port, () => {
      console.log(`Server initialized and ready for action! 🤖`);
      console.log('     /\\_/\\');
      console.log('    / o o \\');
      console.log('   (   "   )');
      console.log('    \\~(*)~/');
      console.log('     /___\\');
      console.log('Welcome to the enchanted forest of code!');
    });
  }
}
