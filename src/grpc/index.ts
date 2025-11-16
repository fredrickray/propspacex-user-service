import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';

// Get the proto file path
const PROTO_PATH = path.join(__dirname, 'proto', 'user.proto');

console.log('📂 Loading proto from:', PROTO_PATH);

// Load the proto file
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

// Load the package definition
const protoDescriptor: any = grpc.loadPackageDefinition(packageDefinition);

console.log('✅ Proto loaded');
console.log('📦 Available packages:', Object.keys(protoDescriptor));

// Check if 'user' package exists
if (protoDescriptor.user) {
  console.log('✅ user package found');
  console.log('🔍 user package contents:', Object.keys(protoDescriptor.user));

  if (protoDescriptor.user.UserService) {
    console.log('✅ UserService found');
    console.log(
      '🔍 UserService methods:',
      Object.keys(protoDescriptor.user.UserService.service || {})
    );
  } else {
    console.error('❌ UserService NOT found in user package');
  }
} else {
  console.error('❌ user package NOT found');
  console.error('Available packages:', Object.keys(protoDescriptor));
}

// Export the protos
export const Protos = {
  user: protoDescriptor.user,
};

// Helper to create gRPC clients
export const createClient = (service: any, address: string) => {
  return new service(address, grpc.credentials.createInsecure());
};
