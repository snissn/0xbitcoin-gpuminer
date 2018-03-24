const Miner = require("./0xbitcoinminer-accel");
const Vault = require("./lib/vault");
const miningLogger = require("./lib/mining-logger");
var prompt = require('prompt');
var pjson = require('./package.json');
var Web3 = require('web3')
var ContractInterface = require("./contracts/DeployedContractInfo")
var NetworkInterface = require("./lib/network-interface");
var PoolInterface = require("./lib/pool-interface");

var web3 = new Web3();

var running = true;

init();

async function init() {
    initSignalHandlers();
    drawLayout();

    console.log('Welcome to 0xBitcoin Miner!')
    //console.log('\n')
    console.log('Type a command to get started.  Type "help" for a list of commands.')
    //console.log('\n')

    getPrompt();
}

async function getPrompt() {
    var result = await promptForCommand();

    getPrompt();
}

function sigHandler(signal) {
    process.exit(128 + signal)
}

function initSignalHandlers() {
    process.on('SIGTERM', sigHandler);
    process.on('SIGINT', sigHandler);
    process.on('SIGBREAK', sigHandler);
    process.on('SIGHUP', sigHandler);
    process.on('SIGWINCH', (sig) => {
        process.stdout.write("\x1b[5r\x1b[5;1f");
    });
    process.on('exit', (sig) => {
        process.stdout.write("\x1b[?25h\x1b!p");
    });
}

function drawLayout() {
    process.stdout.write( "\x1b[2J\x1b(0" );
    process.stdout.write( "\x1b[1;1flqqqqqqqqqqqqqqqqqqqqqqqqqqwqqqqqqqqqqqqqqqqqqqqqqqqqqqwqqqqqqqqqqqqqqqqqqqqqqqk" );
    process.stdout.write( "\x1b[4;1fmqqqqqqqqqqqqqqqqqqqqqqqqqqvqqqqqqqqqqqqqqqqqqqqqqqqqqqvqqqqqqqqqqqqqqqqqqqqqqqj" );
    process.stdout.write( "\x1b[2;1fx\x1b[2;28fx\x1b[2;56fx\x1b[2;80fx" );
    process.stdout.write( "\x1b[3;1fx\x1b[3;28fx\x1b[3;56fx\x1b[3;80fx" );
    process.stdout.write( "\x1b(B\x1b[2;2fChallenge:" );
    process.stdout.write( "\x1b[3;2fDifficulty:" );
    process.stdout.write( "\x1b[2;30fHashes this round" );
    process.stdout.write( "\x1b[2;76fSols" );
    process.stdout.write( "\x1b[3;76fMH/s" );
    process.stdout.write( "\x1b[s\x1b[2;74f\x1b[38;5;221m0\x1b[0m\x1b[u" );
    process.stdout.write( "\x1b[1;58fv" + pjson.version );
    process.stdout.write( "\x1b[5r\x1b[5;1f" );
}

async function promptForCommand() {
    return new Promise(function (fulfilled, rejected) {
        //console.log('')
        prompt.start();
        prompt.get(['command'], async function (err, result) {
            if (err) {
                console.log(err);
                rejected(err);
            } else {
                var response = await handleCommand(result)
                fulfilled(response);
            }
        });
    });
}

/*
if (process.argv.length <= 2) {
console. log("Please add a subsystem parameter (use 'npm run help' for help)");
process. exit(-1);
}

var subsystem_name =  process.argv[2] ;
var subsystem_command = process.argv[3] ;
var subsystem_option = process.argv[4] ;
*/

async function handleCommand(result) {
    var split_command = result.command.split(' ');
    //console.log( split_command )

    var subsystem_name = split_command[0];
    var subsystem_command = split_command[1];
    var subsystem_option = split_command[2];

    if (subsystem_name == 'account') {
        if (subsystem_command === 'new' || subsystem_command === 'list') {
            Vault.requirePassword(true) //for encryption of private key !
        }

        var unlocked = await Vault.init(web3, miningLogger);
        if (!unlocked) return false;

        await Vault.handleAccountCommand(subsystem_command, subsystem_option)
    }

    if (subsystem_name == 'contract') {
        var unlocked = await Vault.init(web3, miningLogger);
        if (!unlocked) return false;

        await Vault.handleContractCommand(subsystem_command, subsystem_option)
    }

    if (subsystem_name == 'config') {
        var unlocked = await Vault.init(web3, miningLogger);
        if (!unlocked) return false;

        await Vault.handleConfigCommand(subsystem_command, subsystem_option)
    }

    if (subsystem_name == 'mine') {
        Vault.requirePassword(true) //for encryption of private key !

        var unlocked = await Vault.init(web3, miningLogger);
        if (!unlocked) return false;

        NetworkInterface.init(web3, Vault, miningLogger);

        Miner.init(web3, Vault, miningLogger);
        Miner.setNetworkInterface(NetworkInterface);

        Miner.setMiningStyle("solo")

        //us command as option -- for cuda or opencl
        subsystem_option = subsystem_command;
        process.stdout.write('\x1b[?25l');
        Miner.mine(subsystem_command, subsystem_option)
    }

    //mining test
    if (subsystem_name == 'test' && subsystem_command == 'mine') {
        Vault.requirePassword(true) //for encryption of private key !

        var infura_provider_url = 'https://ropsten.infura.io/gmXEVo5luMPUGPqg6mhy';
        var ropsten_contract_address = ContractInterface.networks.testnet.contracts._0xbitcointoken.blockchain_address

        Vault.setWeb3ProviderUrl(infura_provider_url);
        Vault.selectContract(ropsten_contract_address);

        web3.setProvider(infura_provider_url)

        var unlocked = await Vault.init(web3, miningLogger);
        if (!unlocked) return false;

        web3.setProvider(infura_provider_url)
        Vault.selectContract(ropsten_contract_address);

        NetworkInterface.init(web3, Vault, miningLogger);

        Miner.init(web3, Vault, miningLogger);
        Miner.setNetworkInterface(NetworkInterface);

        Miner.setMiningStyle("solo")
        process.stdout.write('\x1b[?25l');
        Miner.mine(subsystem_command, subsystem_option)
    }

    if (subsystem_name == 'pool') {
        var unlocked = await Vault.init(web3, miningLogger);
        if (!unlocked) return false;

        await PoolInterface.init(web3, subsystem_command, Vault, miningLogger);
        await PoolInterface.handlePoolCommand(subsystem_command, subsystem_option)

        if (subsystem_command == "mine") {
            Miner.init(web3, Vault, miningLogger);
            Miner.setNetworkInterface(PoolInterface);
            Miner.setMiningStyle("pool")
            process.stdout.write('\x1b[?25l');
            Miner.mine(subsystem_command, subsystem_option)
        }
    }

    if (subsystem_name == 'help') {
        //console.log('\n\n')
        console.log('--0xBitcoin Miner Help--')
        console.log('Available commands:\n')

        //console.log('\n');
        console.log('"account new" - Create a new mining account')
        console.log('"account list" - List all mining accounts')
        console.log('"account select 0x####" - Select a primary mining account by address')
        console.log('"account balance" - List the ether and token balance of your selected account\n')

        //console.log('\n');
        console.log('"contract list" - List the selected token contract to mine')
        console.log('"contract select 0x####" - Select a PoW token contract to mine\n')

        //console.log('\n');
        console.log('"config list" - Show your current configuration')
        console.log('"config gasprice #" - Set the gasprice used to submit PoW to the token smartcontract ')
        //  console.log('"config cpu_threads #" - Set the number of CPU cores to use for mining ')
        console.log('"config web3provider http://----:####" - Set the web3 provider url for submitting ethereum transactions\n')

        //console.log('\n');
        console.log('"pool mine" - Begin mining into a pool')
        console.log('"pool mine cuda" - Begin mining into a pool using CUDA GPU')
        console.log('"pool mine opengl" - Begin mining into a pool using OPENGL GPU')
        console.log('"pool list" - List the selected mining pool')
        console.log('"pool select http://####.com:####" - Select a pool to mine into\n')

        //console.log('\n');
        console.log('"test mine" - Begin mining on Ropsten')
        console.log('"mine" - Begin mining')
        console.log('"mine cuda" - Begin mining using CUDA GPU')
        console.log('"mine opengl" - Begin mining using OPENGL GPU')
        //  console.log('\n')
        //  console.log('Encrypted data vault stored at '+ Vault.get0xBitcoinLocalFolderPath())

        //console.log('\n\n')
    }
}
//init();
