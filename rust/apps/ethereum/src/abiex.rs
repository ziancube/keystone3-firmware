use crate::bindings;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::{string::String, vec::Vec};
use anyhow::Ok as Okk;
use ethabi::ethereum_types::U256;

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

fn amount_format(token_info: &TokenInfo, amount: U256) -> String {
    // format with decimals, e.g. decimals 8, amount 110000000 -> 1.1
    if amount == U256::max_value() {
        return "unlimited".to_string();
    }

    let units = 10u128.pow(token_info.decimals);
    // 整数部分
    let amount = amount / units;
    // 小数部分
    let decimal = amount % units;

    if decimal == U256::zero() {
        format!("{}{}", amount, token_info.symbol)
    } else {
        format!("{}.{}{}", amount, decimal, token_info.symbol)
    }
}

pub fn contract_call_parse(
    chain_id: u64,
    address: &[u8; 20],
    data: &[u8],
) -> anyhow::Result<ContractCall> {
    if data.len() < 4 {
        return Err(anyhow::anyhow!("invalid data"));
    }

    let selector = &data[..4].try_into()?;
    let params = &data[4..];

    let call = match selector {
        Erc20Transfer::SELECTOR => {
            let transfer = Erc20Transfer::parse(chain_id, address, params)?;
            ContractCall::Transfer(transfer)
        }
        Erc20Approval::SELECTOR => {
            let approval = Erc20Approval::parse(chain_id, address, params)?;
            ContractCall::Approval(approval)
        }
        Permit2Approval::SELECTOR => {
            let approve = Permit2Approval::parse(chain_id, address, params)?;
            ContractCall::Approval(approve.into())
        }
        Erc721TransferFrom::SELECTOR => {
            let transfer_from = Erc721TransferFrom::parse(chain_id, address, params)?;
            ContractCall::TransferFrom(transfer_from)
        }
        // safeTransferFrom(address from,address to,uint256 tokenId)
        // 0x42842e0e
        &[0x42, 0x84, 0x2e, 0x0e] => {
            let transfer_from = Erc721TransferFrom::parse(chain_id, address, params)?;
            ContractCall::TransferFrom(transfer_from)
        }
        Erc721SafeTransferFrom::SELECTOR => {
            let safe_transfer_from = Erc721SafeTransferFrom::parse(chain_id, address, params)?;
            ContractCall::TransferFrom(safe_transfer_from.into())
        }
        ExecuteBatch::SELECTOR => {
            let execute_batch = ExecuteBatch::parse(chain_id, address, params)?;
            ContractCall::Batch(execute_batch)
        }
        // executeBatchAndSkipFailures(Call[] calls)
        // 0x27bea2c6
        &[0x27, 0xbe, 0xa2, 0xc6] => {
            let execute_batch = ExecuteBatch::parse(chain_id, address, params)?;
            ContractCall::Batch(execute_batch)
        }
        HandleOps::SELECTOR => {
            let ops = HandleOps::parse(chain_id, address, params)?;
            ops.into_contract_call()
        }
        _ => {
            return Err(anyhow::anyhow!(
                "method not found {}",
                hex::encode(selector)
            ));
        }
    };
    Ok(call)
}

pub trait ContractCallable {
    const SELECTOR: &'static [u8; 4];
    fn method() -> ethabi::Function;
    fn from_tokens(
        chain_id: u64,
        address: &[u8; 20],
        tokens: &[ethabi::Token],
    ) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn parse(chain_id: u64, address: &[u8; 20], data: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let method = Self::method();
        let inputs = method.inputs.clone();
        let tokens = method
            .decode_input(data)
            .map_err(|_| anyhow::anyhow!("invalid data"))?;
        if inputs.len() != tokens.len() {
            return Err(anyhow::anyhow!("invalid data"));
        }
        Self::from_tokens(chain_id, address, &tokens)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Erc20Transfer {
    to: String,
    amount: String,
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
    ) -> anyhow::Result<Self> {
        let to = tokens.get(0).ok_or(anyhow::anyhow!("invalid data"))?;
        let amount = tokens.get(1).ok_or(anyhow::anyhow!("invalid data"))?;
        let (to, amount) = match (to, amount) {
            (ethabi::Token::Address(to), ethabi::Token::Uint(amount)) => Okk((to, amount)),
            _ => return Err(anyhow::anyhow!("invalid data")),
        }?;
        let to = format!("0x{:x}", to);
        let token_info = get_token_info(chain_id, address);
        let amount = amount_format(&token_info, amount.into());

        Ok(Self { to, amount })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Erc20Approval {
    spender: String,
    amount: String,
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
    ) -> anyhow::Result<Self> {
        let spender = tokens.get(0).ok_or(anyhow::anyhow!("invalid data"))?;
        let amount = tokens.get(1).ok_or(anyhow::anyhow!("invalid data"))?;
        let (spender, amount) = match (spender, amount) {
            (ethabi::Token::Address(spender), ethabi::Token::Uint(amount)) => {
                Okk((spender, amount))
            }
            _ => return Err(anyhow::anyhow!("invalid data")),
        }?;
        let spender = format!("0x{:x}", spender);
        let token_info = get_token_info(chain_id, address);
        let amount = amount_format(&token_info, amount.into());

        Ok(Self { spender, amount })
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
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let token = tokens.get(0).ok_or(anyhow::anyhow!("invalid data"))?;
        let spender = tokens.get(1).ok_or(anyhow::anyhow!("invalid data"))?;
        let amount = tokens.get(2).ok_or(anyhow::anyhow!("invalid data"))?;
        let expiration = tokens.get(3).ok_or(anyhow::anyhow!("invalid data"))?;
        let (token, spender, amount, expiration) = match (token, spender, amount, expiration) {
            (
                ethabi::Token::Address(token),
                ethabi::Token::Address(spender),
                ethabi::Token::Uint(amount),
                ethabi::Token::Uint(expiration),
            ) => Okk((token, spender, amount, expiration)),
            _ => return Err(anyhow::anyhow!("invalid data")),
        }?;
        let token = format!("0x{:x}", token);
        let spender = format!("0x{:x}", spender);
        let token_info = get_token_info(chain_id, address);
        let amount = amount_format(&token_info, amount.into());
        let expiration = expiration.to_string();
        Ok(Self {
            token,
            spender,
            amount,
            expiration,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Erc721TransferFrom {
    from: String,
    to: String,
    token_id: String,
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
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let from = tokens.get(0).ok_or(anyhow::anyhow!("invalid data"))?;
        let to = tokens.get(1).ok_or(anyhow::anyhow!("invalid data"))?;
        let token_id = tokens.get(2).ok_or(anyhow::anyhow!("invalid data"))?;
        let (from, to, token_id) = match (from, to, token_id) {
            (
                ethabi::Token::Address(from),
                ethabi::Token::Address(to),
                ethabi::Token::Uint(token_id),
            ) => Okk((from, to, token_id)),
            _ => return Err(anyhow::anyhow!("invalid data")),
        }?;
        let from = format!("0x{:x}", from);
        let to = format!("0x{:x}", to);
        let token_id = token_id.to_string();

        Ok(Self { from, to, token_id })
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
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let from = tokens.get(0).ok_or(anyhow::anyhow!("invalid data"))?;
        let to = tokens.get(1).ok_or(anyhow::anyhow!("invalid data"))?;
        let token_id = tokens.get(2).ok_or(anyhow::anyhow!("invalid data"))?;
        let (from, to, token_id) = match (from, to, token_id) {
            (
                ethabi::Token::Address(from),
                ethabi::Token::Address(to),
                ethabi::Token::Uint(token_id),
            ) => Okk((from, to, token_id)),
            _ => return Err(anyhow::anyhow!("invalid data")),
        }?;
        let from = format!("0x{:x}", from);
        let to = format!("0x{:x}", to);
        let token_id = token_id.to_string();
        Ok(Self { from, to, token_id })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BatchCall {
    Transfer(Erc20Transfer),
    Approval(Erc20Approval),
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecuteBatch(Vec<BatchCall>);

impl BatchCall {
    pub fn parse_call(
        chain_id: u64,
        _address: &[u8; 20],
        token: &ethabi::Token,
    ) -> anyhow::Result<Self> {
        /* struct Call {
         *     address target;
         *     uint256 value;
         *     bytes data;
         * }
         */
        let call = if let ethabi::Token::Tuple(call) = token {
            call
        } else {
            return Err(anyhow::anyhow!("Unknown call"));
        };

        let target = call.get(0).ok_or(anyhow::anyhow!("invalid data"))?;
        let value = call.get(1).ok_or(anyhow::anyhow!("invalid data"))?;
        let data = call.get(2).ok_or(anyhow::anyhow!("invalid data"))?;
        let (target, _value, data) = match (target, value, data) {
            (
                ethabi::Token::Address(target),
                ethabi::Token::Uint(value),
                ethabi::Token::Bytes(data),
            ) => Okk((target, value, data)),
            _ => return Err(anyhow::anyhow!("Unknown call")),
        }?;
        match contract_call_parse(chain_id, &target.to_fixed_bytes(), &data) {
            Ok(ContractCall::Transfer(erc20_transfer)) => Ok(Self::Transfer(erc20_transfer)),
            Ok(ContractCall::Approval(erc20_approval)) => Ok(Self::Approval(erc20_approval)),
            _ => Ok(Self::Unknown),
        }
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
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let calls = tokens.get(0).ok_or(anyhow::anyhow!("invalid data"))?;

        let calls = if let ethabi::Token::Array(calls) = calls {
            calls
        } else {
            return Err(anyhow::anyhow!("invalid data"));
        };
        // calls.iter().map(|call| {
        //     let parsed = match BatchCall::parse_call(call) {
        //         Ok(parsed) => parsed,
        //         _ => return Err(anyhow::anyhow!("invalid data")),
        //     };
        // }).filter_map(Result::ok).collect::<Vec<_>>())

        let calls = calls
            .iter()
            .map(|call| {
                BatchCall::parse_call(chain_id, address, call).unwrap_or(BatchCall::Unknown)
            })
            .collect::<Vec<_>>();
        Ok(Self(calls))
    }
}

struct HandleOps {
    ops: Vec<ContractCall>,
}

impl HandleOps {
    pub fn into_contract_call(&self) -> ContractCall {
        match self.ops.len() {
            0 => panic!("ops is empty"),
            1 => self.ops[0].clone(),
            _ => {
                let calls = self
                    .ops
                    .iter()
                    .map(|op| match op {
                        ContractCall::Transfer(transfer) => {
                            BatchCall::Transfer(transfer.clone())
                        }
                        ContractCall::Approval(approval) => {
                            BatchCall::Approval(approval.clone())
                        }
                        _ => BatchCall::Unknown,
                    })
                    .collect::<Vec<_>>();
                ContractCall::Batch(ExecuteBatch(calls))
            }
        }
    }
}

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
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let ops = tokens.get(0).ok_or(anyhow::anyhow!("invalid data"))?;
        let beneficiary = tokens.get(1).ok_or(anyhow::anyhow!("invalid data"))?;
        let ops = if let ethabi::Token::Array(ops) = ops {
            ops
        } else {
            return Err(anyhow::anyhow!("invalid data"));
        };

        let mut calls = Vec::new();
        for op in ops {
            let op = if let ethabi::Token::Tuple(op) = op {
                op
            } else {
                return Err(anyhow::anyhow!("invalid data"));
            };
            let data = op.get(3).ok_or(anyhow::anyhow!("invalid data"))?;
            let data = if let ethabi::Token::Bytes(data) = data {
                data
            } else {
                return Err(anyhow::anyhow!("invalid data"));
            };

            let call = contract_call_parse(chain_id, address, data)?;
            calls.push(call);
        }

        Ok(Self { ops: calls })
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
    /// ExecuteBatch
    Batch(ExecuteBatch),
}
