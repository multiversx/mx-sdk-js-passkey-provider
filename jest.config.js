module.exports = {
  verbose: true,
  testEnvironment: 'jsdom',
  testTimeout: 10000,
  moduleDirectories: ['node_modules', 'src'],
  roots: ['<rootDir>/src'],
  transform: {
    '^.+\\.[t|j]sx?$': 'ts-jest'
  }
};
