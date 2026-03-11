import { Router } from 'express';
import Web3Controller from './web3.controller';

const web3Router = Router();

web3Router.post('/nonce', Web3Controller.requestNonce.bind(Web3Controller));
web3Router.post('/verify', Web3Controller.verifySignature.bind(Web3Controller));
web3Router.post('/link', Web3Controller.linkWallet.bind(Web3Controller));

export default web3Router;
