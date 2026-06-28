use crate::bindings;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::{string::String, vec::Vec};
use ethabi::ethereum_types::U256;
use crate::errors::{EthereumError, Result};

struct TokenInfo {
    symbol: String,
    decimals: u32,
}

// get token info from `C` function
fn get_token_info(chain_id: u64, address: &[u8; 20]) -> TokenInfo {
    let mut buf = [cty::c_char::default(); 16];
    let mut decimals = 0;
    unsafe {
        bindings::get_token_info(chain_id, address.as_ptr(), buf.as_mut_ptr(), &mut decimals);
    }
    let symbol = unsafe { CString::from_raw(buf.as_mut_ptr()).to_string_lossy().into() };
    TokenInfo { symbol, decimals }
}

fn amount_format(token_info: &TokenInfo, amount: &U256) -> String {
    if amount == &U256::max_value() {
        return "unlimited".to_string();
    }

    // 10^decimals 作为 base（U256）
    let decimals = token_info.decimals;
    let ten = U256::from(10u64);

    // 10^decimals，注意要用 U256 的 pow / 自己循环相乘
    let mut base = U256::one();
    for _ in 0..decimals {
        base *= ten;
    }

    let integer = amount / base;
    let decimal = amount % base;

    // 纯整数（小数部分为 0）
    if decimal.is_zero() {
        return format!("{} {}", integer, token_info.symbol);
    }

    // 将 decimal 转为字符串，再根据 decimals 补零
    // decimal 最大是 10^decimals - 1，转成十进制字符串
    let mut decimal_str = decimal.to_string();

    // 需要的位数：decimals
    let decimals_usize = decimals as usize;
    if decimal_str.len() < decimals_usize {
        let zeros_to_pad = decimals_usize - decimal_str.len();
        let padding = "0".repeat(zeros_to_pad);
        decimal_str = format!("{}{}", padding, decimal_str);
    }

    // 可选：去掉小数部分末尾多余的 0（比如 1.230000 -> 1.23）
    // 如果你希望保留所有位，比如始终显示 1.23000000，就注释掉这一段
    while decimal_str.ends_with('0') {
        decimal_str.pop();
    }

    // 处理一下全是 0 的情况（理论上 is_zero 已经在上面返回了，这里只是保险）
    if decimal_str.is_empty() {
        format!("{} {}", integer, token_info.symbol)
    } else {
        format!("{}.{} {}", integer, decimal_str, token_info.symbol)
    }
}

pub fn contract_call_parse(
    chain_id: u64,
    address: &[u8; 20],
    data: &[u8],
) -> Result<Vec<ContractCall>> {
    if data.len() < 4 {
        return Err(EthereumError::InvalidContractABI);
    }

    let selector = &data[..4].try_into().map_err(|_| EthereumError::InvalidContractABI)?;
    let params = &data[4..];

    let calls = match selector {
        Erc20Transfer::SELECTOR => {
            Erc20Transfer::parse(chain_id, address, params)?
        }
        Erc20Approval::SELECTOR => {
            Erc20Approval::parse(chain_id, address, params)?
        }
        Permit2Approval::SELECTOR => {
            Permit2Approval::parse(chain_id, address, params)?
        }
        Erc721TransferFrom::SELECTOR => {
            Erc721TransferFrom::parse(chain_id, address, params)?
        }
        // safeTransferFrom(address from,address to,uint256 tokenId)
        // 0x42842e0e
        &[0x42, 0x84, 0x2e, 0x0e] => {
            Erc721TransferFrom::parse(chain_id, address, params)?
        }
        Erc721SafeTransferFrom::SELECTOR => {
            Erc721SafeTransferFrom::parse(chain_id, address, params)?
        }
        ExecuteBatch::SELECTOR => {
            ExecuteBatch::parse(chain_id, address, params)?
        }
        // executeBatchAndSkipFailures(Call[] calls)
        // 0x27bea2c6
        &[0x27, 0xbe, 0xa2, 0xc6] => {
            ExecuteBatch::parse(chain_id, address, params)?
        }
        HandleOps::SELECTOR => {
            HandleOps::parse(chain_id, address, params)?
        }
        _ => vec![ContractCall::Unknown(data.to_vec())],
    };
    Ok(calls)
}

pub trait ContractCallable {
    const SELECTOR: &'static [u8; 4];
    fn method() -> ethabi::Function;
    fn from_tokens(
        chain_id: u64,
        address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> Result<Vec<ContractCall>>
    where
        Self: Sized;

    fn parse(chain_id: u64, address: &[u8; 20], data: &[u8]) -> Result<Vec<ContractCall>>
    where
        Self: Sized,
    {
        let method = Self::method();
        let inputs = method.inputs.clone();
        let tokens = method
            .decode_input(data)
            .map_err(|_| EthereumError::InvalidContractABI)?;
        if inputs.len() != tokens.len() {
            return Err(EthereumError::InvalidContractABI);
        }
        Self::from_tokens(chain_id, address, &tokens)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Erc20Transfer {
    pub to: String,
    pub amount: String,
}

impl ContractCallable for Erc20Transfer {
    // transfer(address to, uint256 amount)
    // 0xa9059cbb
    const SELECTOR: &'static [u8; 4] = &[0xa9, 0x05, 0x9c, 0xbb];

    fn method() -> ethabi::Function {
        // transfer(address to, uint256 amount)
        let inputs = vec![
            ethabi::Param {
                name: "to".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
            ethabi::Param {
                name: "amount".to_string(),
                kind: ethabi::ParamType::Uint(256),
                internal_type: None,
            },
        ];

        let function = ethabi::Function {
            name: "transfer".to_string(),
            inputs,
            outputs: vec![],
            #[allow(deprecated)]
            constant: None,
            state_mutability: ethabi::StateMutability::Payable,
        };
        function
    }

    fn from_tokens(
        chain_id: u64,
        address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> Result<Vec<ContractCall>> {
        let to = tokens.get(0).ok_or(EthereumError::InvalidContractABI)?;
        let amount = tokens.get(1).ok_or(EthereumError::InvalidContractABI)?;
        let to = match to {
            ethabi::Token::Address(to) => to,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let amount = match amount {
            ethabi::Token::Uint(amount) => amount,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let to = format!("0x{:x}", to);
        let token_info = get_token_info(chain_id, address);
        let amount = amount_format(&token_info, amount);

        Ok(vec![ContractCall::Transfer(Erc20Transfer { to, amount })])
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Erc20Approval {
    pub spender: String,
    pub amount: String,
}

impl ContractCallable for Erc20Approval {
    // approve(address spender, uint256 amount)
    // 0x095EA7B3
    const SELECTOR: &'static [u8; 4] = &[0x09, 0x5e, 0xa7, 0xb3];

    fn method() -> ethabi::Function {
        // approve(address spender, uint256 amount)
        let inputs = vec![
            ethabi::Param {
                name: "spender".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
            ethabi::Param {
                name: "amount".to_string(),
                kind: ethabi::ParamType::Uint(256),
                internal_type: None,
            },
        ];
        let function = ethabi::Function {
            name: "approve".to_string(),
            inputs,
            outputs: vec![],
            #[allow(deprecated)]
            constant: None,
            state_mutability: ethabi::StateMutability::Payable,
        };
        function
    }

    fn from_tokens(
        chain_id: u64,
        address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> Result<Vec<ContractCall>> {
        let spender = tokens.get(0).ok_or(EthereumError::InvalidContractABI)?;
        let amount = tokens.get(1).ok_or(EthereumError::InvalidContractABI)?;
        let spender = match spender {
            ethabi::Token::Address(spender) => spender,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let amount = match amount {
            ethabi::Token::Uint(amount) => amount,
            _ => return Err(EthereumError::InvalidContractABI),
        };

        let spender = format!("0x{:x}", spender);
        let token_info = get_token_info(chain_id, address);
        let mut unlimited_value: U256 = 100000000000u128.into();
        unlimited_value *= U256::from(10u128.pow(token_info.decimals));
        let amount = if amount >= &unlimited_value {
            "unlimited".to_string()
        } else {
            amount_format(&token_info, amount.into())
        };

        Ok(vec![ContractCall::Approval(Erc20Approval { spender, amount })])
    }
}

impl From<Permit2Approval> for Erc20Approval {
    fn from(permit: Permit2Approval) -> Self {
        Self {
            spender: permit.spender,
            amount: permit.amount,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct Permit2Approval {
    token: String,
    spender: String,
    amount: String,
    expiration: String,
}

impl ContractCallable for Permit2Approval {
    // approve(address token, address spender, uint160 amount, uint48 expiration)
    // 0x87517c45
    const SELECTOR: &'static [u8; 4] = &[0x87, 0x51, 0x7c, 0x45];

    fn method() -> ethabi::Function {
        // approve(address token, address spender, uint160 amount, uint48 expiration)
        let inputs = vec![
            ethabi::Param {
                name: "token".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
            ethabi::Param {
                name: "spender".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
            ethabi::Param {
                name: "amount".to_string(),
                kind: ethabi::ParamType::Uint(160),
                internal_type: None,
            },
            ethabi::Param {
                name: "expiration".to_string(),
                kind: ethabi::ParamType::Uint(48),
                internal_type: None,
            },
        ];
        let function = ethabi::Function {
            name: "approve".to_string(),
            inputs,
            outputs: vec![],
            #[allow(deprecated)]
            constant: None,
            state_mutability: ethabi::StateMutability::Payable,
        };
        function
    }

    fn from_tokens(
        chain_id: u64,
        address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> Result<Vec<ContractCall>>
    where
        Self: Sized,
    {
        let token = tokens.get(0).ok_or(EthereumError::InvalidContractABI)?;
        let spender = tokens.get(1).ok_or(EthereumError::InvalidContractABI)?;
        let amount = tokens.get(2).ok_or(EthereumError::InvalidContractABI)?;
        let expiration = tokens.get(3).ok_or(EthereumError::InvalidContractABI)?;

        let token = match token {
            ethabi::Token::Address(token) => token,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let spender = match spender {
            ethabi::Token::Address(spender) => spender,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let amount = match amount {
            ethabi::Token::Uint(amount) => amount,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let expiration = match expiration {
            ethabi::Token::Uint(expiration) => expiration,
            _ => return Err(EthereumError::InvalidContractABI),
        };

        let token = format!("0x{:x}", token);
        let spender = format!("0x{:x}", spender);
        let token_info = get_token_info(chain_id, address);
        let amount = amount_format(&token_info, amount.into());
        let expiration = expiration.to_string();
        Ok(vec![ContractCall::Approval(Erc20Approval {
            spender,
            amount,
        })])
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Erc721TransferFrom {
    pub from: String,
    pub to: String,
    pub token_id: String,
}

impl ContractCallable for Erc721TransferFrom {
    // transferFrom(address from, address to, uint256 tokenId)
    // 0x23B872DD
    const SELECTOR: &'static [u8; 4] = &[0x23, 0xb8, 0x72, 0xdd];

    fn method() -> ethabi::Function {
        // transferFrom(address from, address to, uint256 tokenId)
        let inputs = vec![
            ethabi::Param {
                name: "from".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
            ethabi::Param {
                name: "to".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
            ethabi::Param {
                name: "token_id".to_string(),
                kind: ethabi::ParamType::Uint(256),
                internal_type: None,
            },
        ];

        let function = ethabi::Function {
            name: "transferFrom".to_string(),
            inputs,
            outputs: vec![],
            #[allow(deprecated)]
            constant: None,
            state_mutability: ethabi::StateMutability::Payable,
        };
        function
    }

    fn from_tokens(
        _chain_id: u64,
        _address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> Result<Vec<ContractCall>>
    where
        Self: Sized,
    {
        let from = tokens.get(0).ok_or(EthereumError::InvalidContractABI)?;
        let to = tokens.get(1).ok_or(EthereumError::InvalidContractABI)?;
        let token_id = tokens.get(2).ok_or(EthereumError::InvalidContractABI)?;

        let from = match from {
            ethabi::Token::Address(from) => from,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let to = match to {
            ethabi::Token::Address(to) => to,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let token_id = match token_id {
            ethabi::Token::Uint(token_id) => token_id,
            _ => return Err(EthereumError::InvalidContractABI),
        };

        let from = format!("0x{:x}", from);
        let to = format!("0x{:x}", to);
        let token_id = token_id.to_string();

        Ok(vec![ContractCall::TransferFrom(Erc721TransferFrom { from, to, token_id })])
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct Erc721SafeTransferFrom {
    from: String,
    to: String,
    token_id: String,
}

impl From<Erc721SafeTransferFrom> for Erc721TransferFrom {
    fn from(transfer_from: Erc721SafeTransferFrom) -> Self {
        Self {
            from: transfer_from.from,
            to: transfer_from.to,
            token_id: transfer_from.token_id,
        }
    }
}

impl ContractCallable for Erc721SafeTransferFrom {
    // safeTransferFrom(address from, address to, uint256 tokenId, bytes data)
    // 0xb88d4fde
    const SELECTOR: &'static [u8; 4] = &[0xb8, 0x8d, 0x4f, 0xde];

    fn method() -> ethabi::Function {
        // safeTransferFrom(address from,address to,uint256 tokenId,bytes data)
        let inputs = vec![
            ethabi::Param {
                name: "from".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
            ethabi::Param {
                name: "to".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
            ethabi::Param {
                name: "token_id".to_string(),
                kind: ethabi::ParamType::Uint(256),
                internal_type: None,
            },
            ethabi::Param {
                name: "data".to_string(),
                kind: ethabi::ParamType::Bytes,
                internal_type: None,
            },
        ];
        let function = ethabi::Function {
            name: "safeTransferFrom".to_string(),
            inputs,
            outputs: vec![],
            #[allow(deprecated)]
            constant: None,
            state_mutability: ethabi::StateMutability::Payable,
        };
        function
    }
    fn from_tokens(
        _chain_id: u64,
        _address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> Result<Vec<ContractCall>>
    where
        Self: Sized,
    {
        let from = tokens.get(0).ok_or(EthereumError::InvalidContractABI)?;
        let to = tokens.get(1).ok_or(EthereumError::InvalidContractABI)?;
        let token_id = tokens.get(2).ok_or(EthereumError::InvalidContractABI)?;

        let from = match from {
            ethabi::Token::Address(from) => from,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let to = match to {
            ethabi::Token::Address(to) => to,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let token_id = match token_id {
            ethabi::Token::Uint(token_id) => token_id,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let from = format!("0x{:x}", from);
        let to = format!("0x{:x}", to);
        let token_id = token_id.to_string();
        Ok(vec![ContractCall::TransferFrom(Erc721TransferFrom { from, to, token_id })])
    }
}


pub struct ExecuteBatch;

impl ExecuteBatch {
    pub fn parse_batch_call(
        chain_id: u64,
        _address: &[u8; 20],
        token: &ethabi::Token,
    ) -> Result<Vec<ContractCall>> {
        /* struct Call {
         *     address target;
         *     uint256 value;
         *     bytes data;
         * }
         */
        let call = if let ethabi::Token::Tuple(call) = token {
            call
        } else {
            return Err(EthereumError::InvalidContractABI);
        };

        let target = call.get(0).ok_or(EthereumError::InvalidContractABI)?;
        let value = call.get(1).ok_or(EthereumError::InvalidContractABI)?;
        let data = call.get(2).ok_or(EthereumError::InvalidContractABI)?;

        let target = match target {
            ethabi::Token::Address(target) => target,
            _ => return Err(EthereumError::InvalidContractABI),
        };

        let value = match value {
            ethabi::Token::Uint(value) => value,
            _ => return Err(EthereumError::InvalidContractABI),
        };
        let data = match data {
            ethabi::Token::Bytes(data) => data,
            _ => return Err(EthereumError::InvalidContractABI),
        };

        contract_call_parse(chain_id, &target.to_fixed_bytes(), &data)
    }
}

impl ContractCallable for ExecuteBatch {
    // ExecuteBatch(bytes memory data)
    // 34fcd5be
    const SELECTOR: &'static [u8; 4] = &[0x34, 0xfc, 0xd5, 0xbe];
    fn method() -> ethabi::Function {
        /*
         * struct Call {
         *     address target;
         *     uint256 value;
         *     bytes data;
         * }
         * executeBatch(Call[] calls)
         */
        let call = ethabi::Param {
            name: "call".to_string(),
            kind: ethabi::ParamType::Tuple(vec![
                ethabi::ParamType::Address,
                ethabi::ParamType::Uint(256),
                ethabi::ParamType::Bytes,
            ]),
            internal_type: None,
        };
        let inputs = vec![ethabi::Param {
            name: "calls".to_string(),
            kind: ethabi::ParamType::Array(Box::new(call.kind.clone())),
            internal_type: None,
        }];

        let function = ethabi::Function {
            name: "executeBatch".to_string(),
            inputs,
            outputs: vec![],
            #[allow(deprecated)]
            constant: None,
            state_mutability: ethabi::StateMutability::Payable,
        };
        function
    }

    fn from_tokens(
        chain_id: u64,
        address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> Result<Vec<ContractCall>>
    where
        Self: Sized,
    {
        let calls = tokens.get(0).ok_or(EthereumError::InvalidContractABI)?;

        let calls = if let ethabi::Token::Array(calls) = calls {
            calls
        } else {
            return Err(EthereumError::InvalidContractABI);
        };

        let mut batch_calls = vec![];
        for call in calls.iter() {
            batch_calls.extend_from_slice(&ExecuteBatch::parse_batch_call(chain_id, address, call)?);
        }
        Ok(batch_calls)
    }
}

struct HandleOps;

impl ContractCallable for HandleOps {
    // handleOps(PackedUserOperation[] ops)
    // 0x765e827f
    const SELECTOR: &'static [u8; 4] = &[0x76, 0x5e, 0x82, 0x7f];

    fn method() -> ethabi::Function {
        /*
        struct PackedUserOperation {
            address sender;
            uint256 nonce;
            bytes initCode;
            bytes callData;
            bytes32 accountGasLimits;
            uint256 preVerificationGas;
            bytes32 gasFees;
            bytes paymasterAndData;
            bytes signature;
        }
        handleOps(PackedUserOperation[] ops, address beneficiary)
        */
        let op = ethabi::ParamType::Tuple(vec![
            ethabi::ParamType::Address,        // sender
            ethabi::ParamType::Uint(256),      // nonce
            ethabi::ParamType::Bytes,          // initCode
            ethabi::ParamType::Bytes,          // callData
            ethabi::ParamType::FixedBytes(32), // accountGasLimits
            ethabi::ParamType::Uint(256),      // preVerificationGas
            ethabi::ParamType::FixedBytes(32), // gasFees
            ethabi::ParamType::Bytes,          // paymasterAndData
            ethabi::ParamType::Bytes,          // signature
        ]);
        let inputs = vec![
            ethabi::Param {
                name: "ops".to_string(),
                kind: ethabi::ParamType::Array(Box::new(op)),
                internal_type: None,
            },
            ethabi::Param {
                name: "beneficiary".to_string(),
                kind: ethabi::ParamType::Address,
                internal_type: None,
            },
        ];
        let function = ethabi::Function {
            name: "handleOps".to_string(),
            inputs,
            outputs: vec![],
            #[allow(deprecated)]
            constant: None,
            state_mutability: ethabi::StateMutability::Payable,
        };
        function
    }

    fn from_tokens(
        chain_id: u64,
        address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> Result<Vec<ContractCall>>
    {
        let ops = tokens.get(0).ok_or(EthereumError::InvalidContractABI)?;
        let beneficiary = tokens.get(1).ok_or(EthereumError::InvalidContractABI)?;
        let ops = if let ethabi::Token::Array(ops) = ops {
            ops
        } else {
            return Err(EthereumError::InvalidContractABI);
        };

        let mut calls = Vec::new();
        for op in ops {
            let op = if let ethabi::Token::Tuple(op) = op {
                op
            } else {
                return Err(EthereumError::InvalidContractABI);
            };
            let data = op.get(3).ok_or(EthereumError::InvalidContractABI)?;
            let data = if let ethabi::Token::Bytes(data) = data {
                data
            } else {
                return Err(EthereumError::InvalidContractABI);
            };

            let call = contract_call_parse(chain_id, address, data)?;
            calls.extend_from_slice(&call);
        }
        Ok(calls)
    }
}

struct Uniswap;
impl Uniswap {
    pub fn method() -> ethabi::Function {
        // execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline)
        // execute(bytes calldata commands, bytes[] calldata inputs)

        let inputs = vec![
            ethabi::Param {
                name: "commands".to_string(),
                kind: ethabi::ParamType::Bytes,
                internal_type: None,
            },
            ethabi::Param {
                name: "inputs".to_string(),
                kind: ethabi::ParamType::Array(Box::new(ethabi::ParamType::Bytes)),
                internal_type: None,
            },
            ethabi::Param {
                name: "deadline".to_string(),
                kind: ethabi::ParamType::Uint(256),
                internal_type: None,
            },
        ];

        let function = ethabi::Function {
            name: "execute".to_string(),
            inputs,
            outputs: vec![],
            #[allow(deprecated)]
            constant: None,
            state_mutability: ethabi::StateMutability::Payable,
        };
        function
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ContractCall {
    /// ERC20: Transfer
    Transfer(Erc20Transfer),
    /// ERC20: Approval
    Approval(Erc20Approval),
    /// ERC721: TransferFrom
    TransferFrom(Erc721TransferFrom),
    /// Unknown
    Unknown(Vec<u8>),
}
