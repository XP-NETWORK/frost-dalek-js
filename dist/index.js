const { existsSync, readFileSync } = require('fs')
const { join } = require('path')

const { platform, arch } = process

let nativeBinding = null
let localFileExisted = false
let loadError = null

function isMusl() {
  // For Node 10
  if (!process.report || typeof process.report.getReport !== 'function') {
    try {
      return readFileSync('/usr/bin/ldd', 'utf8').includes('musl')
    } catch (e) {
      return true
    }
  } else {
    const { glibcVersionRuntime } = process.report.getReport().header
    return !glibcVersionRuntime
  }
}

switch (platform) {
  case 'android':
    switch (arch) {
      case 'arm64':
        localFileExisted = existsSync(join(__dirname, 'frost-dalek.android-arm64.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./frost-dalek.android-arm64.node')
          } else {
            nativeBinding = require('frost-dalek-android-arm64')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm':
        localFileExisted = existsSync(join(__dirname, 'frost-dalek.android-arm-eabi.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./frost-dalek.android-arm-eabi.node')
          } else {
            nativeBinding = require('frost-dalek-android-arm-eabi')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Android ${arch}`)
    }
    break
  case 'win32':
    switch (arch) {
      case 'x64':
        localFileExisted = existsSync(
          join(__dirname, 'frost-dalek.win32-x64-msvc.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./frost-dalek.win32-x64-msvc.node')
          } else {
            nativeBinding = require('frost-dalek-win32-x64-msvc')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'ia32':
        localFileExisted = existsSync(
          join(__dirname, 'frost-dalek.win32-ia32-msvc.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./frost-dalek.win32-ia32-msvc.node')
          } else {
            nativeBinding = require('frost-dalek-win32-ia32-msvc')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm64':
        localFileExisted = existsSync(
          join(__dirname, 'frost-dalek.win32-arm64-msvc.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./frost-dalek.win32-arm64-msvc.node')
          } else {
            nativeBinding = require('frost-dalek-win32-arm64-msvc')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Windows: ${arch}`)
    }
    break
  case 'darwin':
    switch (arch) {
      case 'x64':
        localFileExisted = existsSync(join(__dirname, 'frost-dalek.darwin-x64.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./frost-dalek.darwin-x64.node')
          } else {
            nativeBinding = require('frost-dalek-darwin-x64')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm64':
        localFileExisted = existsSync(
          join(__dirname, 'frost-dalek.darwin-arm64.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./frost-dalek.darwin-arm64.node')
          } else {
            nativeBinding = require('frost-dalek-darwin-arm64')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on macOS: ${arch}`)
    }
    break
  case 'freebsd':
    if (arch !== 'x64') {
      throw new Error(`Unsupported architecture on FreeBSD: ${arch}`)
    }
    localFileExisted = existsSync(join(__dirname, 'frost-dalek.freebsd-x64.node'))
    try {
      if (localFileExisted) {
        nativeBinding = require('./frost-dalek.freebsd-x64.node')
      } else {
        nativeBinding = require('frost-dalek-freebsd-x64')
      }
    } catch (e) {
      loadError = e
    }
    break
  case 'linux':
    switch (arch) {
      case 'x64':
        if (isMusl()) {
          localFileExisted = existsSync(
            join(__dirname, 'frost-dalek.linux-x64-musl.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./frost-dalek.linux-x64-musl.node')
            } else {
              nativeBinding = require('frost-dalek-linux-x64-musl')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(
            join(__dirname, 'frost-dalek.linux-x64-gnu.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./frost-dalek.linux-x64-gnu.node')
            } else {
              nativeBinding = require('frost-dalek-linux-x64-gnu')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 'arm64':
        if (isMusl()) {
          localFileExisted = existsSync(
            join(__dirname, 'frost-dalek.linux-arm64-musl.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./frost-dalek.linux-arm64-musl.node')
            } else {
              nativeBinding = require('frost-dalek-linux-arm64-musl')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(
            join(__dirname, 'frost-dalek.linux-arm64-gnu.node')
          )
          try {
            if (localFileExisted) {
              nativeBinding = require('./frost-dalek.linux-arm64-gnu.node')
            } else {
              nativeBinding = require('frost-dalek-linux-arm64-gnu')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 'arm':
        localFileExisted = existsSync(
          join(__dirname, 'frost-dalek.linux-arm-gnueabihf.node')
        )
        try {
          if (localFileExisted) {
            nativeBinding = require('./frost-dalek.linux-arm-gnueabihf.node')
          } else {
            nativeBinding = require('frost-dalek-linux-arm-gnueabihf')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Linux: ${arch}`)
    }
    break
  default:
    throw new Error(`Unsupported OS: ${platform}, architecture: ${arch}`)
}

if (!nativeBinding) {
  if (loadError) {
    throw loadError
  }
  throw new Error(`Failed to load native binding`)
}

const { participate, generateTheirSharesAndVerifyParticipants, derivePubkAndGroupKey, genCommitmentShareLists, discardSecretShareHandle, getAggregatorSigners, signPartial, aggregateSignatures, validateSignature, groupKeyToEd25519 } = nativeBinding

module.exports.participate = participate
module.exports.generateTheirSharesAndVerifyParticipants = generateTheirSharesAndVerifyParticipants
module.exports.derivePubkAndGroupKey = derivePubkAndGroupKey
module.exports.genCommitmentShareLists = genCommitmentShareLists
module.exports.discardSecretShareHandle = discardSecretShareHandle
module.exports.getAggregatorSigners = getAggregatorSigners
module.exports.signPartial = signPartial
module.exports.aggregateSignatures = aggregateSignatures
module.exports.validateSignature = validateSignature
module.exports.groupKeyToEd25519 = groupKeyToEd25519