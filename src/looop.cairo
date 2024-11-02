// SPDX-License-Identifier: MIT
pub use starknet::{
    ContractAddress, class_hash::ClassHash, syscalls::deploy_syscall, SyscallResultTrait,
    storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess},
    account::Call
};

#[derive(Drop, Serde, starknet::Store)]
struct User {
    id: u32,
    email: felt252,
    token_id: u256,
    token_contract_address: ContractAddress,
    acct_address: ContractAddress,
    pass_key: felt252
}

#[starknet::interface]
pub trait ILooopContract<TContractState> {
    fn upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn version(self: @TContractState) -> u8;
    fn register_account(
        ref self: TContractState,
        nft_contract_address: ContractAddress,
        nft_token_id: u256,
        implementation_hash: felt252,
        salt: felt252,
        pass_key: felt252
    ) -> ContractAddress;
    fn fetch_account(
        self: @TContractState,
        nft_contract_address: ContractAddress,
        nft_token_id: u256,
        implementation_hash: felt252,
        salt: felt252
    ) -> ContractAddress;
    fn get_account_count(self: @TContractState) -> u32;
    fn get_account_owner_details(self: @TContractState, email: felt252) -> User;
}


#[starknet::contract]
pub mod LooopContract {
    use super::{ILooopContract, User};

    use core::starknet::SyscallResultTrait;
    use core::hash::{HashStateTrait, HashStateExTrait};
    use core::poseidon::PoseidonTrait;

    use starknet::{
        ClassHash, ContractAddress, storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess}, get_caller_address, get_contract_address, account::Call
    };

    use looop_contract::interfaces::IRegistry::{
        IRegistryDispatcher, IRegistryDispatcherTrait, IRegistryLibraryDispatcher
    };

    // use token_bound_accounts::{
    //     interfaces::IAccount::IAccount,
    //     account::{account::AccountComponent::InternalTrait, AccountComponent}
    // };

    // component!(path: AccountComponent, storage: account, event: AccountEvent);

    // #[abi(embed_v0)]
    // impl AccountImpl = AccountComponent::AccountImpl<ContractState>;

    #[storage]
    struct Storage {
        account_count: u32,
        version: u8,
        owner: ContractAddress,
        users: Map::<felt252, User>,
        // #[substorage(v0)]
        // account: AccountComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        // #[flat]
        // AccountEvent: AccountComponent::Event,
        CreatedAccount: CreatedAccount
    }


    #[derive(Drop, starknet::Event)]
    struct CreatedAccount {
        id: u32,
        address: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, _owner: ContractAddress,) {
        self.owner.write(_owner);
    }

    const REGISTRY_CLASS_HASH: felt252 =
        0x46163525551f5a50ed027548e86e1ad023c44e0eeb0733f0dab2fb1fdc31ed0;

    #[abi(embed_v0)]
    impl LooopContractImpl of ILooopContract<ContractState> {
        fn register_account(
            ref self: ContractState,
            nft_contract_address: ContractAddress,
            nft_token_id: u256,
            implementation_hash: felt252,
            salt: felt252,
            pass_key: felt252
        ) -> ContractAddress {
            let account_address = IRegistryLibraryDispatcher {
                class_hash: REGISTRY_CLASS_HASH.try_into().unwrap()
            }
            .create_account(implementation_hash, nft_contract_address, nft_token_id, salt);

            let hashed_pass_key = PoseidonTrait::new().update_with(pass_key).finalize();

            let _user_instance = User {
                id: self.account_count.read() + 1,
                email: salt,
                token_id: nft_token_id,
                token_contract_address: nft_contract_address,
                acct_address: account_address,
                pass_key: hashed_pass_key
            };

            self.users.write(salt, _user_instance);

            self.account_count.write(self.account_count.read() + 1);

            self.emit(CreatedAccount {id: self.account_count.read() + 1, address: account_address});

            account_address
        }

        fn fetch_account(
            self: @ContractState,
            nft_contract_address: ContractAddress,
            nft_token_id: u256,
            implementation_hash: felt252,
            salt: felt252
        ) -> ContractAddress {
            let account_address = IRegistryLibraryDispatcher {
                class_hash: REGISTRY_CLASS_HASH.try_into().unwrap()
            }
            .get_account(implementation_hash, nft_contract_address, nft_token_id, salt);

            account_address
        }

        fn get_account_owner_details(self: @ContractState, email: felt252) -> User {
            self.users.read(email)
        }

        fn get_account_count(self: @ContractState) -> u32 {
            self.account_count.read()
        }

        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            let caller = get_caller_address();

            assert(self.owner.read() == caller, 'NOT_OWNER');

            starknet::syscalls::replace_class_syscall(new_class_hash).unwrap_syscall();

            self.version.write(self.version.read() + 1);
        }

        fn version(self: @ContractState) -> u8 {
            self.version.read()
        }
    }
}
