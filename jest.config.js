module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  rootDir: '.', // Root directory of your project
  testMatch: [
    '**/test/**/*.test.ts', // Matches test files in 'src/test/'
    '**/__tests__/**/*.test.ts', // Additionally, matches '__tests__' directories if present
  ],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1', // Maps '@/...' to 'src/...'
  },
  transform: {
    '^.+\\.ts?$': ['ts-jest', { tsconfig: 'tsconfig.json' }], // Move ts-jest config here
  },
};
