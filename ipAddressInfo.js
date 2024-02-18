/*
    ipAddressInfo.js is a library to validate ip addresses and get subnet info based on a given ip address and subnet
*/


function ipToBinary(ipAddress) {
    //convvert an ip address or subnet mask into binary
    return ipAddress.split('.').map(octet => parseInt(octet).toString(2).padStart(8, '0')).join('');
}

function binaryToIP(binaryAddress) {
    // convert a binary ip or netmask into decimal form
    let start = 0;
    let stop = 8;
    let ip = "";
    for(let i = 0; i < 4; i++){
        ip = ip + parseInt(binaryAddress.slice(start, stop),2) + (i<3 ? "." : "");
        start += 8;
        stop += 8
    }
    return ip;
} 

function nextIPAddress(ipAddress) {
    //returns the next ip address
    let ipArray = ipAddress.split(".").map(octet => parseInt(octet));
    let shifted = (ipArray[0] << 24) | (ipArray[1] << 16) | (ipArray[2] << 8) | (ipArray[3] << 0);
    shifted++;
    return [shifted >> 24 & 0xff, shifted >> 16 & 0xff, shifted >> 8 & 0xff, shifted >> 0 & 0xff].join(".")

}

function previousIPAddress(ipAddress) {
    //returns the previous ip address
    let ipArray = ipAddress.split(".").map(octet => parseInt(octet));
    let shifted = (ipArray[0] << 24) | (ipArray[1] << 16) | (ipArray[2] << 8) | (ipArray[3] << 0);
    shifted--;
    return [shifted >> 24 & 0xff, shifted >> 16 & 0xff, shifted >> 8 & 0xff, shifted >> 0 & 0xff].join(".")

}

function validIP(ip) {
    let valid = false;
    let ipv4 = new RegExp("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|" +
    "[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]" + 
    "?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    if (ip.match(ipv4)) {
        valid = true;
    } 
    return valid
}

function validSubnet(subnet) {

    let valid = false;
    
    if (/^\d{1,2}$/.test(subnet)) {
        if(parseInt(subnet) <= 32 && parseInt(subnet) >=8){
            valid = true;
        }
    } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(subnet)){
        let regExMask = new RegExp("^(((255\.){3}(255|254|252|248|240|224|192|128|0+))|" +
        "((255\.){2}(255|254|252|248|240|224|192|128|0+)\.0)|((255\.)(255|254|252|248|240|224|192|128|0+)"+
        "(\.0+){2})|((255|254|252|248|240|224|192|128|0+)(\.0+){3}))$");

        if (subnet.match(regExMask)) {
            valid = true;
        }
    } 
    
    return valid;
}


       
function getSubnetInfo(ipAddress, subnet) {
    /*
    Returns an object with ip address, subnet mask, wildcard mask, broadcast address, network address,
    CIDR, first host, last host, and the total possible hosts in the given subnet as properties
    */
    
    if(validIP(ipAddress) && validSubnet(subnet)) {
        let binaryIP;
        let binarySubnetMask;
        let binaryNetwork;
        let binaryBroadcast;
        let subnetBit;
        let subnetMask;
        let networkBits;
        let wildcardMask;
        let networkAddress;
        let firstHost;
        let lastHost;
        let broadcast;
        let numberOfHosts;

        if (/^\d{1,2}$/.test(subnet)) {
            subnetBit = subnet;
            binarySubnetMask = "1".repeat(subnetBit) + "0".repeat(32-subnetBit);
            subnetMask = binaryToIP(binarySubnetMask);
        } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(subnet)){
            subnetMask = subnet;
            binarySubnetMask = ipToBinary(subnetMask);
            subnetBit = binarySubnetMask.indexOf("0");
        }

        binaryIP = ipToBinary(ipAddress);
        networkBits = binaryIP.slice(0, subnetBit);
        binaryBroadcast = networkBits + "1".repeat(32 - subnetBit);
        broadcast = binaryToIP(binaryBroadcast);
        binaryNetwork = networkBits + "0".repeat(32-subnetBit);
        networkAddress = binaryToIP(binaryNetwork)
        wildcardMask = binaryToIP("0".repeat(subnetBit) + "1".repeat(32-subnetBit));
        numberOfHosts = Math.pow(2, (32-subnetBit)) - 2;
        firstHost = nextIPAddress(networkAddress);
        lastHost = previousIPAddress(broadcast);
        
        return {
            ip: ipAddress,
            mask: subnetMask,
            networkAddress: networkAddress,
            wildcard: wildcardMask,
            cidr: subnetBit,
            firstHost: firstHost,
            lastHost: lastHost,
            broadcast: broadcast,
            hosts: numberOfHosts
        }
    } else {
        console.error("IP address or subnet mask is not valid. Please check and try again.");
    }
    
    
}


