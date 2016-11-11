/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */

'use strict';

var helpers = require('./helpers');

var mock = {};
module.exports = mock;

var identities = mock.identities = {};
var userName;

// identity with permission to add public keys
userName = 'regularUser';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].identity.sysResourceRole.push({
  sysRole: 'bedrock-key-http.test',
  generateResource: 'id'
});
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqv8gApfU3FhZx1gyKmBU\n' +
    'czZ1Ba3DQbqcGRJiwWz6wrr9E/K0PcpRws/+GPc1znG4cKLdxkdyA2zROUt/lbaM\n' +
    'TU+/kZzRh3ICZZOuo8kJpGqxPDIm7L1lIcBLOWu/UEV2VaWNOENwiQbh61VJlR+k\n' +
    'HK9LhQxYYZT554MYaXzcSRTC/RzHDTAocf+B1go8tawPEixgs93+HHXoLPGypmqn\n' +
    'lBKAjmGMwizbWFccDQqv0yZfAFpdVY2MNKlDSUNMnZyUgBZNpGOGPm9zi9aMFT2d\n' +
    'DrN9fpWMdu0QeZrJrDHzk6TKwtKrBB9xNMuHGYdPxy8Ix0uNmUt0mqt6H5Vhl4O0\n' +
    '0QIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpQIBAAKCAQEAqv8gApfU3FhZx1gyKmBUczZ1Ba3DQbqcGRJiwWz6wrr9E/K0\n' +
    'PcpRws/+GPc1znG4cKLdxkdyA2zROUt/lbaMTU+/kZzRh3ICZZOuo8kJpGqxPDIm\n' +
    '7L1lIcBLOWu/UEV2VaWNOENwiQbh61VJlR+kHK9LhQxYYZT554MYaXzcSRTC/RzH\n' +
    'DTAocf+B1go8tawPEixgs93+HHXoLPGypmqnlBKAjmGMwizbWFccDQqv0yZfAFpd\n' +
    'VY2MNKlDSUNMnZyUgBZNpGOGPm9zi9aMFT2dDrN9fpWMdu0QeZrJrDHzk6TKwtKr\n' +
    'BB9xNMuHGYdPxy8Ix0uNmUt0mqt6H5Vhl4O00QIDAQABAoIBAQCpA3yXM42AsY8j\n' +
    'mwgSnJ48NqJaF5L8P7+UhHi6KMZ+fSYydl0zCevge4bzFD3JrNuZ8VD1b57AxejT\n' +
    'Ec2so/9vVxjJi1AK6WR3FA608rumGJLQJd4Vd2ojfxabTeWOKOo642R/LSFpPzVE\n' +
    'T0toqxqiA53IhxhAc2jDLO+PLIvrao0Y8bWWq36tbxsAplrv8Gms6ZRwfKoX5P32\n' +
    'azBpJOqneNdSMRPHky6t2uiYyuPeG9pbuaClkD7Ss9lpH0V1DLQmAAlP9I0Aa06B\n' +
    'a9zPFPb3Ae8F0HO/tsf8gIvrlT38JvLe5VuCS7/LQNCZguyPZuZOXLDmdETfm1FD\n' +
    'q56rCV7VAoGBANmQ7EqDfxmUygTXlqaCQqNzY5pYKItM6RFHc9I+ADBWsLbuKtfP\n' +
    'XUMHQx6PvwCMBpjZkM7doGdzOHb0l3rW8zQONayqQxN9Pjd7K+dkSY6k0SScw46w\n' +
    '0AexDQSM/0ahVAHfXXi1GbKwlonM0nn/7JHz7n/fL9HwV8T3hAGClbPDAoGBAMk0\n' +
    'K5d+Ov55sKW0ZatZ0vTnfBCSrVEfG6FkcyK7uiSsMdWo2/De0VtJF7od2DM5UyP6\n' +
    'Y/DSVk4oPepbug5oGdu8t1Q3jbS61A7i/dssirQC4hEFAtoTGsVfaH8wu4AKyWd7\n' +
    '0rUmSrnyqNr4mfQBjdaXByvWO9rdEfZcZqaSQ4/bAoGAKy/CR7Q8eYZ4Z2eoBtta\n' +
    'gPl5rvyK58PXi8+EJRqbjPzYTSePp5EI8TIy15EvF9uzv4mIXhfOLFrJvYsluoOK\n' +
    'eS3M575QXEEDJZ40g9T7aO48eakIhH2CfdReQiX+0jVZ6Jk/A6PnOvokl6vpp7/u\n' +
    'ZLZoBEf4RRMRSQ7czDPwpWMCgYEAlNWZtWuz+hBMgpcqahF9AprF5ICL4qkvSDjF\n' +
    'Dpltfbk+9/z8DXbVyUANZCi1iFbMUJ3lFfyRySjtfBI0VHnfPvOfbZXWpi1ZtlVl\n' +
    'UZ7mT3ief9aEIIrnT79ezk9fM71G9NzcphHYTyrYi3pAcAZCRM3diSjlh+XmZqY9\n' +
    'bNRfU+cCgYEAoBYwp0PJ1QEp3lSmb+gJiTxfNwIrP+VLkWYzPREpSbghDYjE2DfC\n' +
    'M8pNbVWpnOfT7OlhN3jw8pxHWap6PxNyVT2W/1AHNGKTK/BfFVn3nVGhOgPgH1AO\n' +
    'sObYxm9gpkNkelXejA/trbLe4hg7RWNYzOztbfbZakdVjMNfXnyw+Q0=\n' +
    '-----END RSA PRIVATE KEY-----\n'
});

// identity with permission to add public keys
userName = 'regularUser2';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].identity.sysResourceRole.push({
  sysRole: 'bedrock-key-http.test',
  generateResource: 'id'
});
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtugBZOFYzNxQK8Cvk9jJ\n' +
    'waG4PpPw2crv492HcuJTWsRwBtFvRjekd2VTk3KhXxqf/cfnJZWooTK+aZEKTYN0\n' +
    'f7KdlPkopgJ7SXqbuuYZWrRLJIECnwNeEytibQAk42LhMuMgEoCeWMxZLOAMwiHz\n' +
    'GlTtz3jSQDuWjeLL09LHFRJUBx0hOc4z/JksiOzD6ClBavQXhhbZYNbznBs3mH+W\n' +
    'TBkEkms0SnOhRp8gi4KiQrtKYbBlkwHG3kiu0Nnww5QiFfrNaK2Sm5XOG5EMHSE9\n' +
    'UObpZkbdd3ziKg2TNlydrpDSyu/oSivykzDRMwzCval2WgeWl5X6tkeZ0HZzuIKb\n' +
    'mwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEogIBAAKCAQEAtugBZOFYzNxQK8Cvk9jJwaG4PpPw2crv492HcuJTWsRwBtFv\n' +
    'Rjekd2VTk3KhXxqf/cfnJZWooTK+aZEKTYN0f7KdlPkopgJ7SXqbuuYZWrRLJIEC\n' +
    'nwNeEytibQAk42LhMuMgEoCeWMxZLOAMwiHzGlTtz3jSQDuWjeLL09LHFRJUBx0h\n' +
    'Oc4z/JksiOzD6ClBavQXhhbZYNbznBs3mH+WTBkEkms0SnOhRp8gi4KiQrtKYbBl\n' +
    'kwHG3kiu0Nnww5QiFfrNaK2Sm5XOG5EMHSE9UObpZkbdd3ziKg2TNlydrpDSyu/o\n' +
    'SivykzDRMwzCval2WgeWl5X6tkeZ0HZzuIKbmwIDAQABAoIBAFnB9tUrpOk7gHhI\n' +
    'IaF7NF86XnEPJpWqehinYM3m9SLI3XTrGCEsMyCIcAAes8Q5C6R9khgmnk8k2L5z\n' +
    'd8vcI7J608wEjYcSFrBTY9LPEkgpy+pJCSFBhMwBcVauSGvx3TOcs+OAjLRk66oS\n' +
    '9Q/bmzIj1WQIFZ2B4HsWfhIgEKRsuqTlqa92331OCiHVJsxlUCRYhvOnAeH1uqva\n' +
    'LTnOAcM4GRNYKSvJ+DOLP4E3tsMIA0TYfvgIF6Enrs+qruetX/hNfisyxA5Gh/lh\n' +
    '/fTviujN/OmwkdbbzqkcofkLm0VwbDsjnQydOjoHd8bD+6/gTxPWO9j2jZ4N4QO5\n' +
    'ard9rEECgYEA312V4/oqz1SPsHcfCl2HIdNscRopP9bRnPXXtX9FQWKF3TbkUU3d\n' +
    'RvFUqfmm4/dT2zeKhV0xykwPqkby2rwec6pDfkInW4Cxcw2lUSxEJvSwY2TjGmX9\n' +
    'y4isA8s6LEZCqHNa5Rfs+hKlXX4w1YJeaT3FJdeSdU1fMQ54Q4spbrsCgYEA0aEk\n' +
    '3ZOw3qg7WarrQlY/erplqKIOXdsOZluXtTvBm0bNiaKx5/ZIK5ig5FVy1NK/tzYW\n' +
    '+eyzJoCSsd8ugZK7lJnrfam2d2nFPP2GCgYIenAbEFoZebra7Rqd5V9jlbBEBux/\n' +
    'gtsthhVwJJc1zo4Zv2Vu0dYFE6AbLV8qrD/oaKECgYEAjE6ODCGl6IyWoeOB1RIB\n' +
    'A2d6U+V6CcbX7r+i2zhx+Wt46QdFDilaGOkZJJhUlBhVTXurALEUyJ1UrcJZZLsM\n' +
    'ad2G/fVyIZFKZhopQT8MJGhJsHW8DmYIsWRNoSh0h0EvN/8WFpgb3M3/oCXXaRa2\n' +
    'VWdewrGSJysN45PSSaNNyGcCgYEAhplRcnRCPLUIZqq4I//9AnBslbp4PwtIU7C7\n' +
    '2EJmLa1oi9dLJAWekV+O7w1ujfhD4P96AT9aSH6Fsm/7DHeKuf+alTVDU6k2W9Lt\n' +
    'HcKB7xvMRNOVR/QSXeuZNo3pA1QKWefAd+UDdfSN7PCqO9ZB8gLPBSzGVbOXv6o7\n' +
    'XB4svAECfylKpp/6ij2noWCe5R3MWznRm1MvfYCA32VAqiCewBd4JWOlrqXZ2gkY\n' +
    'xg8UxWzEokaJ7yN4AwUHxIuXfesYjP5YYHUcy6TmbuMc8fn9iyK2Ve2El0F7Ir+p\n' +
    'G29vqwnSoor0xh0Wy3id4aH0dONEqIluAJ7f81Gm2IBTqLc7rUY=\n' +
    '-----END RSA PRIVATE KEY-----\n'
});

// identity with permission to access all public keys (Admin)
userName = 'adminUser';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].identity.sysResourceRole.push({
  sysRole: 'bedrock-key-http.test'
});
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp7sV50vxdDmviLjOy/w/\n' +
    'Lb0NhLN6ZuxiH9Tllaq9X6KAGUAA4/xR5LCBnQ/IGcriXu+HoB9BGP3wwtjXM/Kr\n' +
    'kDhnO5tRgxZb5+dV0eFP2kzQZBt98Yq9kCoP7NUsv1HX8bt3wVBRLcVrbmOXTumZ\n' +
    'PF7LrRqQoklnFdGAnIZc7TXmcY/Sz5Q+CKhPgWNxTIczm4Swmv9hxLd6BEHHcM1S\n' +
    'pUaf6gu28TvMyISjUyMf4Oq154BRnjoif2d9xggRYrxGnT8yVm//MA/54Xu6c4/6\n' +
    'jR7l7kDngbL65eUfKMtH+Vqt1aJPBXkm62rjUFRmIhGd2V9uiPQNe4CcoYRocllg\n' +
    '1wIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEAp7sV50vxdDmviLjOy/w/Lb0NhLN6ZuxiH9Tllaq9X6KAGUAA\n' +
    '4/xR5LCBnQ/IGcriXu+HoB9BGP3wwtjXM/KrkDhnO5tRgxZb5+dV0eFP2kzQZBt9\n' +
    '8Yq9kCoP7NUsv1HX8bt3wVBRLcVrbmOXTumZPF7LrRqQoklnFdGAnIZc7TXmcY/S\n' +
    'z5Q+CKhPgWNxTIczm4Swmv9hxLd6BEHHcM1SpUaf6gu28TvMyISjUyMf4Oq154BR\n' +
    'njoif2d9xggRYrxGnT8yVm//MA/54Xu6c4/6jR7l7kDngbL65eUfKMtH+Vqt1aJP\n' +
    'BXkm62rjUFRmIhGd2V9uiPQNe4CcoYRocllg1wIDAQABAoIBAAyZfiS4zLN5Xdk8\n' +
    'YLRsB2btK6XLQaeXnCtd970NbVpQv6Sl7SszGge+xo3A0Lw3RFfzUFHT5zT0ZnCM\n' +
    'j2XklcSoqACPQ0lAlbjO5OB2N2RjnsfWVNifHmxE7JtSzCC3Ciyrc2x/FwoEKXTK\n' +
    'YGRaIduqF0yykSjPsMGv0iRv520eH0agGmZANOyV4TpPDumRAOPLwz/JN6wd5Bg6\n' +
    '/06IN+JmdFGSXUipowofWvuFz8UV0+/7Gitff87zssmNM3axlq+X8wLkXE0R3c5y\n' +
    'X+tSFN5tDiWYYqotJkdDz2Wh3exsJgwwQTkcddu9NtsiRfrkGogbyyNovyIM1T9v\n' +
    'BfbQ8JECgYEAz5STL3InyWYpN1PUXuDz1bbTIL0I/1r/ICjWxP9/T0bXjVF2eL6j\n' +
    'K3VYVc84vmcNRd4iiokimYOyBDouSprP0KqtxGf950oQ50wJzWOkNts2p5a8tZMe\n' +
    '13CLQyCmUPzaw5OLYMLX1VzdnI1EDb2aHTr+55sN5hw0Qvw52D5DnakCgYEAztrw\n' +
    'aqpnxDTw4cZ6d9dgsbqknIbWOV3wSvqCfGiyglKcsSUoXFtRJQDjIddIl01fiuEC\n' +
    '+fdqrMnQUh3enJ0f0VsBMyBzfMHze5vvinwH1cPMpz7kb14hTAyrNNOBf1FB2olQ\n' +
    'oVUAvd05rh8ZO0NxIub0CmB2etgZD9e3y9tTGn8CgYEAla8Te5Ebs5Thf64JY+le\n' +
    'qutMzzzA8jIR6oTIagG7MdVptdPaVDNTwhC6BBaLWnFBFvKZgcBlnMFkarvxiYac\n' +
    '+GE7MHe0lUXJbqBcKSkCzzO/85U0utI92Siko2E1zQyoS4Nna/zUWly+yRbszeO8\n' +
    '7/sMuMIMgbQw02TB6XbslxECgYBlPRxLaCkvCyYVqflIa/3kHk/wV8HDA+nWGHMC\n' +
    'ho9PXzVXMbNmOD8nmB6R8naRromjQ+scAe6QsJknh3zrM69d3Gdi6W/8UERla/U5\n' +
    '1uhSw+iGti5BH1W2jcDBMv7/G/raBTiULTEWu44+XPQRYDmf9l7cMUfraZYifdZz\n' +
    'jF1I6wKBgBsEcAsKTrFid82GF4IYNGd8gcjGPq2ANWXzukjkizQyJvyjYLqYhpVk\n' +
    '5BJfyH08n5FZE9CbA0lbZw7kZ+UKt4UhijGK5VyKvyNQ0rtOfS8SlEbeT0JqlIOw\n' +
    'FGTKsHlxFTcYrL/eg91tp+5uXZ+NI4Y+3ZYVTdNB/efIO+zWOxuw\n' +
    '-----END RSA PRIVATE KEY-----\n'
});

// identity with no permissions
userName = 'noPermissionUser';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].keys = helpers.createKeyPair({
  userName: userName,
  userId: identities[userName].identity.id,
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApiYhM3TtNcdDvG5vDSBx\n' +
    'i4MHNyUUi+SY3Sg5jCETKC0535Ma7R7eurPbanQjvR/95zCU+/4fNt6FzaDRBFrW\n' +
    'RL3TALNEeIyM/Sm68NoP/hF3Q0UanRzZX7mKkqftim+7dRxXsOZWVKWiRuKFQEJ2\n' +
    'KSHUtfGc2ySGeghyAL3APzRk3QaTv1sSYegueWseA9Lv279c+L1tNbYvxkELigRn\n' +
    'M8qyV33MyaIn3ep5yCTLdBkHlvgS632In34EBE32zw4vsW/M8KqymHENTl6fTMsw\n' +
    'q1J4J8O5rWfkbNiiBEzBYGJfQul1gI7iCg6A+CCB9wEr0g3eGNHtSF3zXDa731gI\n' +
    'XQIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEApiYhM3TtNcdDvG5vDSBxi4MHNyUUi+SY3Sg5jCETKC0535Ma\n' +
    '7R7eurPbanQjvR/95zCU+/4fNt6FzaDRBFrWRL3TALNEeIyM/Sm68NoP/hF3Q0Ua\n' +
    'nRzZX7mKkqftim+7dRxXsOZWVKWiRuKFQEJ2KSHUtfGc2ySGeghyAL3APzRk3QaT\n' +
    'v1sSYegueWseA9Lv279c+L1tNbYvxkELigRnM8qyV33MyaIn3ep5yCTLdBkHlvgS\n' +
    '632In34EBE32zw4vsW/M8KqymHENTl6fTMswq1J4J8O5rWfkbNiiBEzBYGJfQul1\n' +
    'gI7iCg6A+CCB9wEr0g3eGNHtSF3zXDa731gIXQIDAQABAoIBADvjjJ4mrIZxACqA\n' +
    'yAi8RBFctpIbDI/sY2l8YVnwZh5aRv0e4lrMgM5dnF5/5I38ZSIbcehvTkMR7LsV\n' +
    'F6JxN8Dph5A+DhVB3GQ40YiVoaQcGZgm5ZPyXSxTDe8VFtuKsNBi2f0K2d2DIr5Y\n' +
    'Ul26Vys2ZZz7rWWUgeClAKrhutVM8XALesWtUVv8/Y/c+SGiRc9c02RyT1gq2KIr\n' +
    '7xWwa/Pk0yOge/upIMl7SbIhDNwcU5KjAEWcPKf+5MRbLv98qSGNhbIycgDjhpWf\n' +
    'uEk5rctCbB/hosPdqVRklChTyXtfGqc3LRcD5C0je2PB8/RmwtCPJde5qJyDiyZl\n' +
    'GjOlGkECgYEA3RpZcM1uHntI4xjKg7ujhCapJNMcH0NcNU35ieSSrUOJyZH+aCjm\n' +
    'juIRg0pzuSzCPMsxmMFVu/K7w7ZttoXPBX3u1m6CSvf6isrbgXgheMAZ5WqCjNXS\n' +
    '3Ljti1N0efw8vEf1dspPeYOaROI/KRnmdMQjpACGoSi0WRoy2Hi7G00CgYEAwF9e\n' +
    'LkzmflmIbDFy0+Jjz/PebwLhIA7fQ3eMDs/Pnv6aoKhqXOZLK7g2sHKWLKHbjC5J\n' +
    'jOqtod3YDr6O/gLgKXN9Ed0hzY4WshjPDTfllMwQBHKRvZA8/TC/4D9L45Ih6JJF\n' +
    'Qe5cgNfHHtLAuGiksCXVFzOTdOPlNYpZRsyxeVECgYAvHgRdY4nJ+R/JNWlCtWPd\n' +
    'L5fv/wUJLIOj4GADILCZN8FPMUtzyvOHE2oD/oO2vHEQH4UMNnccvFeDF4c91DoP\n' +
    'w4x4KcieTUYY+a3ZY05OuzFJkG8NsCtlWgtVG43AyR3wSa1niSlyjbb8YvJuwdQ4\n' +
    'oeuucWY/RbtZGZooQ2IsKQKBgApzI8KQGtUyN97osLwhyBo7vRF6ro/3PtmDXPBR\n' +
    'CY4xdmTTwTNaryqozw+2qcGy6SIsQYKOHPB2BI6Ie2wA6/xUca7OvE9WMJVsE5M8\n' +
    'PhRfIV+ceZ46f5WhWEruJUkvXvgrOefi8tNs5TwfZqidxpRq+bBQ9Omcl47Y/RCD\n' +
    'fgCBAoGBAJrJuMbrdzNK4812DZJ/ESHg77CYd0NYdN6H4faQGWPZYJF0JF+dSTC9\n' +
    'v4pjsDANOPG5LP3vZrDSnRe/ifylfUYnvw11G72ueF87T3pftH6b99lmcYX20KJG\n' +
    'omXWUsjDJgN5r1qJdCshpgni3yhp5+m9Yz2x/nRrHY8KUBm3cmwy\n' +
    '-----END RSA PRIVATE KEY-----\n'
});

mock.goodKeyPair = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpPmWDG3MCn3simEGNIe\n' +
    'seNe3epn81gLnWXjup458yXgjUYFqKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQ\n' +
    'mmQjh28BhMXHq94HgQ90nKQ3KTpAMOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o\n' +
    '9OhzpqJwFzQj7Nxx2dg/3LnkcsP1/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3Wrnmn\n' +
    'LxNEwvWKj3iDp4JyLeV3WxWIf3ExgdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J\n' +
    '8xqsqrvR3ICdYIevjFknMHX1LZB5R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYy\n' +
    'jwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpQIBAAKCAQEArpPmWDG3MCn3simEGNIeseNe3epn81gLnWXjup458yXgjUYF\n' +
    'qKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQmmQjh28BhMXHq94HgQ90nKQ3KTpA\n' +
    'MOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o9OhzpqJwFzQj7Nxx2dg/3LnkcsP1\n' +
    '/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3WrnmnLxNEwvWKj3iDp4JyLeV3WxWIf3Ex\n' +
    'gdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J8xqsqrvR3ICdYIevjFknMHX1LZB5\n' +
    'R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYyjwIDAQABAoIBAQCJZBpfBFlQDWdD\n' +
    'jorIYe0IQJGzgjvm9j7F058iik2+/us3I4lmjnPGkYlEs4uAn7df087pVOhEDatp\n' +
    'D0r2bTZ92xtfBcyjKmgW6XjsaDZ05IQI7TABi4lnXAD9wWWU5hXqfpLT6UPvQArx\n' +
    'xBWclR8mRx5lYOdoS3+OdHshX5/63ACCYlYonTov2TkIjvozQY4H5F0M0aaF3naM\n' +
    'GFRus8qmJTrfBmQPBBwRJnPJLQk03hAHXRyUHGHAo5QVZlEdvf5LeOTIfsw2X9ro\n' +
    'xGFBIruS2JfrWHbApTOIYlzCQBpBBM28l4/rvkfEDmugYaZE9LdpQfddQJOrnqXF\n' +
    'xHARbO0JAoGBANjqe0YKPsW/i6MEN0kOhcpYm19GYceXTSgErDsTDeEcvv6o9Chi\n' +
    'baRyNK1tZ+Kff4rMw74Vw+uIfpq5ROiTJ67p094jVmZhgmKsXAqIbapcR+R+bygO\n' +
    'Q3UioXCTCYvPKWL8n8FdgFsBohK4+y5NCgNZ8tIxqvB1fLQDs9AdhOxjAoGBAM4I\n' +
    'g/fUY5oBFS4KrMCQbz+DPzDTgMGrX0ZC7BD6S9jX/AI4Wwm11t/WWGuijUiQaFFd\n' +
    'YUHXVoe6qRuYemND2zUvbpBK84SVVxF3a6lncmpnxiLe2lHbj5/Dh+y/C7HKGiTC\n' +
    'jTfvfe8YAeTpC1djIH0sWPC6n91ulyA23Nz4h6rlAoGBAJVUT0s3cGF4bSvrkhfU\n' +
    'TJyxhT0A2f2qlm5PUTZV9r8bqAzuyS8oG60TBlrCL7te7FHkh3jLyRXT4LypgNvP\n' +
    'uoj65mVN1IQk6rr9R1vk8gJPBxsxQ1rC/wObtKIoR3EdS7OekGhw8xUzuZzEBf+o\n' +
    '/5SxDq5PjQt/BjtzNQ231LNbAoGAGDab+8Y0Jmc2LAEJKGBREq/D/2L74MbZHZLD\n' +
    '14Ly4vsPHNuup0d9hzTTk2K5I+wEtns48Nnzy2O+eAXFbGEPJAL9BWwpjk1WvDDC\n' +
    'sFf99E9Z08NI+RHKoUYDdWlGYJCV3fgXTJmSvUSfBF32/UAjE1Lg6PmlzAoxLJIG\n' +
    'BtoWZ5kCgYEAnvcfRx56ZvUkWJiSI0me+M20A74IGwxDPF87XuGPSEqcoLSc1qJM\n' +
    '6LtOFUE7nFVEqFMN2IhW59qb2eCg7XpeEQic4aqNkc8WtuMEavHRTucsEWk+ypZv\n' +
    'JCxLDG7o3iSqT+DNbYnDI7aUCuM6Guji98q3IvBnW5hj+jbmo4sfRDQ=\n' +
    '-----END RSA PRIVATE KEY-----\n'
};

// the public and private keys are valid, but do not match
mock.badKeyPair = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwWDnqsCB2eYSGicntVHU\n' +
    '1nqzBdlInoLkNzrjp5nd7b57kZQwJteYtlnjVa4WD39iNnJbsLlpFsUJSL7TvgzC\n' +
    'JNuey9/6QvYpZNuXz2a8EdOA0tPu6GmVdV5ZW7eJRWUZXhE01nrHbfGVWqU5xVy6\n' +
    'mcI9JB+vc151sleyrdVZkt+MvZy9D1gMre/bb8AM6YxkMoW/kwhkDpu6LcX8xhws\n' +
    'MmX0+W+i2BKauSDNrooRpFJhPBsvAJc2a8QN8Qa2QOrDEANR/h+hS66/A/TGNNcl\n' +
    'eItkVXFDeLhta724RXHwhY4mJN9xU9/B6TPtz4v0NCpB6t8UyDw6lxRJM5ws3wM1\n' +
    'lQIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpQIBAAKCAQEArpPmWDG3MCn3simEGNIeseNe3epn81gLnWXjup458yXgjUYF\n' +
    'qKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQmmQjh28BhMXHq94HgQ90nKQ3KTpA\n' +
    'MOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o9OhzpqJwFzQj7Nxx2dg/3LnkcsP1\n' +
    '/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3WrnmnLxNEwvWKj3iDp4JyLeV3WxWIf3Ex\n' +
    'gdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J8xqsqrvR3ICdYIevjFknMHX1LZB5\n' +
    'R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYyjwIDAQABAoIBAQCJZBpfBFlQDWdD\n' +
    'jorIYe0IQJGzgjvm9j7F058iik2+/us3I4lmjnPGkYlEs4uAn7df087pVOhEDatp\n' +
    'D0r2bTZ92xtfBcyjKmgW6XjsaDZ05IQI7TABi4lnXAD9wWWU5hXqfpLT6UPvQArx\n' +
    'xBWclR8mRx5lYOdoS3+OdHshX5/63ACCYlYonTov2TkIjvozQY4H5F0M0aaF3naM\n' +
    'GFRus8qmJTrfBmQPBBwRJnPJLQk03hAHXRyUHGHAo5QVZlEdvf5LeOTIfsw2X9ro\n' +
    'xGFBIruS2JfrWHbApTOIYlzCQBpBBM28l4/rvkfEDmugYaZE9LdpQfddQJOrnqXF\n' +
    'xHARbO0JAoGBANjqe0YKPsW/i6MEN0kOhcpYm19GYceXTSgErDsTDeEcvv6o9Chi\n' +
    'baRyNK1tZ+Kff4rMw74Vw+uIfpq5ROiTJ67p094jVmZhgmKsXAqIbapcR+R+bygO\n' +
    'Q3UioXCTCYvPKWL8n8FdgFsBohK4+y5NCgNZ8tIxqvB1fLQDs9AdhOxjAoGBAM4I\n' +
    'g/fUY5oBFS4KrMCQbz+DPzDTgMGrX0ZC7BD6S9jX/AI4Wwm11t/WWGuijUiQaFFd\n' +
    'YUHXVoe6qRuYemND2zUvbpBK84SVVxF3a6lncmpnxiLe2lHbj5/Dh+y/C7HKGiTC\n' +
    'jTfvfe8YAeTpC1djIH0sWPC6n91ulyA23Nz4h6rlAoGBAJVUT0s3cGF4bSvrkhfU\n' +
    'TJyxhT0A2f2qlm5PUTZV9r8bqAzuyS8oG60TBlrCL7te7FHkh3jLyRXT4LypgNvP\n' +
    'uoj65mVN1IQk6rr9R1vk8gJPBxsxQ1rC/wObtKIoR3EdS7OekGhw8xUzuZzEBf+o\n' +
    '/5SxDq5PjQt/BjtzNQ231LNbAoGAGDab+8Y0Jmc2LAEJKGBREq/D/2L74MbZHZLD\n' +
    '14Ly4vsPHNuup0d9hzTTk2K5I+wEtns48Nnzy2O+eAXFbGEPJAL9BWwpjk1WvDDC\n' +
    'sFf99E9Z08NI+RHKoUYDdWlGYJCV3fgXTJmSvUSfBF32/UAjE1Lg6PmlzAoxLJIG\n' +
    'BtoWZ5kCgYEAnvcfRx56ZvUkWJiSI0me+M20A74IGwxDPF87XuGPSEqcoLSc1qJM\n' +
    '6LtOFUE7nFVEqFMN2IhW59qb2eCg7XpeEQic4aqNkc8WtuMEavHRTucsEWk+ypZv\n' +
    'JCxLDG7o3iSqT+DNbYnDI7aUCuM6Guji98q3IvBnW5hj+jbmo4sfRDQ=\n' +
    '-----END RSA PRIVATE KEY-----\n'
};

/*
// the public key is invalid, the private key is valid
mock.badPublicKey = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpQIBAAKCAQEArpPmWDG3MCn3simEGNIeseNe3epn81gLnWXjup458yXgjUYF\n' +
    'qKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQmmQjh28BhMXHq94HgQ90nKQ3KTpA\n' +
    'MOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o9OhzpqJwFzQj7Nxx2dg/3LnkcsP1\n' +
    '/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3WrnmnLxNEwvWKj3iDp4JyLeV3WxWIf3Ex\n' +
    'gdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J8xqsqrvR3ICdYIevjFknMHX1LZB5\n' +
    'R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYyjwIDAQABAoIBAQCJZBpfBFlQDWdD\n' +
    'jorIYe0IQJGzgjvm9j7F058iik2+/us3I4lmjnPGkYlEs4uAn7df087pVOhEDatp\n' +
    'D0r2bTZ92xtfBcyjKmgW6XjsaDZ05IQI7TABi4lnXAD9wWWU5hXqfpLT6UPvQArx\n' +
    'xBWclR8mRx5lYOdoS3+OdHshX5/63ACCYlYonTov2TkIjvozQY4H5F0M0aaF3naM\n' +
    'GFRus8qmJTrfBmQPBBwRJnPJLQk03hAHXRyUHGHAo5QVZlEdvf5LeOTIfsw2X9ro\n' +
    'xGFBIruS2JfrWHbApTOIYlzCQBpBBM28l4/rvkfEDmugYaZE9LdpQfddQJOrnqXF\n' +
    'xHARbO0JAoGBANjqe0YKPsW/i6MEN0kOhcpYm19GYceXTSgErDsTDeEcvv6o9Chi\n' +
    'baRyNK1tZ+Kff4rMw74Vw+uIfpq5ROiTJ67p094jVmZhgmKsXAqIbapcR+R+bygO\n' +
    'Q3UioXCTCYvPKWL8n8FdgFsBohK4+y5NCgNZ8tIxqvB1fLQDs9AdhOxjAoGBAM4I\n' +
    'g/fUY5oBFS4KrMCQbz+DPzDTgMGrX0ZC7BD6S9jX/AI4Wwm11t/WWGuijUiQaFFd\n' +
    'YUHXVoe6qRuYemND2zUvbpBK84SVVxF3a6lncmpnxiLe2lHbj5/Dh+y/C7HKGiTC\n' +
    'jTfvfe8YAeTpC1djIH0sWPC6n91ulyA23Nz4h6rlAoGBAJVUT0s3cGF4bSvrkhfU\n' +
    'TJyxhT0A2f2qlm5PUTZV9r8bqAzuyS8oG60TBlrCL7te7FHkh3jLyRXT4LypgNvP\n' +
    'uoj65mVN1IQk6rr9R1vk8gJPBxsxQ1rC/wObtKIoR3EdS7OekGhw8xUzuZzEBf+o\n' +
    '/5SxDq5PjQt/BjtzNQ231LNbAoGAGDab+8Y0Jmc2LAEJKGBREq/D/2L74MbZHZLD\n' +
    '14Ly4vsPHNuup0d9hzTTk2K5I+wEtns48Nnzy2O+eAXFbGEPJAL9BWwpjk1WvDDC\n' +
    'sFf99E9Z08NI+RHKoUYDdWlGYJCV3fgXTJmSvUSfBF32/UAjE1Lg6PmlzAoxLJIG\n' +
    'BtoWZ5kCgYEAnvcfRx56ZvUkWJiSI0me+M20A74IGwxDPF87XuGPSEqcoLSc1qJM\n' +
    '6LtOFUE7nFVEqFMN2IhW59qb2eCg7XpeEQic4aqNkc8WtuMEavHRTucsEWk+ypZv\n' +
    'JCxLDG7o3iSqT+DNbYnDI7aUCuM6Guji98q3IvBnW5hj+jbmo4sfRDQ=\n' +
    '-----END RSA PRIVATE KEY-----\n'
};

// the public key is valid, the private key is invalid
mock.badPrivateKey = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpPmWDG3MCn3simEGNIe\n' +
    'seNe3epn81gLnWXjup458yXgjUYFqKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQ\n' +
    'mmQjh28BhMXHq94HgQ90nKQ3KTpAMOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o\n' +
    '9OhzpqJwFzQj7Nxx2dg/3LnkcsP1/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3Wrnmn\n' +
    'LxNEwvWKj3iDp4JyLeV3WxWIf3ExgdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J\n' +
    '8xqsqrvR3ICdYIevjFknMHX1LZB5R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYy\n' +
    'jwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' +
    '-----END RSA PRIVATE KEY-----\n'
};
*/
