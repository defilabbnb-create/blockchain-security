const { hardhatNetworkConfig } = require('./dynamic-execution-boundary.cjs');

module.exports = { networks: { hardhat: hardhatNetworkConfig(process.env) }, solidity: '0.8.24' };
