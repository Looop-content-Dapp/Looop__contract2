// SPDX-License-Identifier: MIT
pub use starknet::{
    ContractAddress, class_hash::ClassHash, syscalls::deploy_syscall, SyscallResultTrait,
    storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess}, account::Call
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
    fn complete_nft_transaction(
        ref self: TContractState,
        nft_address: ContractAddress,
        buyer: ContractAddress,
        token_id: u256,
        amount: u256
    );
    fn update_agreement_uri(ref self: TContractState, agreement_uri: ByteArray);
    fn update_whitelisted_signer(ref self: TContractState, new_signer: ContractAddress);
    fn update_payment_token(ref self: TContractState, token_address: ContractAddress);
    fn sign_agreement(ref self: TContractState);
    fn withdraw(ref self: TContractState, token: ContractAddress, recipient: ContractAddress, amount: u256);
    fn get_account_count(self: @TContractState) -> u32;
    fn get_account_owner_details(self: @TContractState, email: felt252) -> User;
    fn check_artist_signed_agreement(self: @TContractState, artist: ContractAddress) -> bool;
    fn get_payment_token_address(self: @TContractState) -> ContractAddress;
    fn get_whitelisted_signer(self: @TContractState) -> ContractAddress;
}


#[starknet::contract]
pub mod LooopContract {
    use super::{ILooopContract, User};

    use core::starknet::SyscallResultTrait;
    use core::hash::{HashStateTrait, HashStateExTrait};
    use core::poseidon::PoseidonTrait;
    use core::num::traits::Zero;

    use starknet::{
        ClassHash, ContractAddress,
        storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry},
        get_caller_address, get_contract_address, get_block_timestamp, account::Call
    };

    use looop_contract::interfaces::IRegistry::{
        IRegistryDispatcher, IRegistryDispatcherTrait, IRegistryLibraryDispatcher
    };

    use looop_contract::interfaces::IERC721::{IERC721, IERC721Dispatcher, IERC721DispatcherTrait};
    use openzeppelin::token::erc20::interface::{IERC20DispatcherTrait, IERC20Dispatcher,};

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
        payment_token: ContractAddress,
        whitelisted_signer: ContractAddress,
        agreement_uri: ByteArray,
        users: Map::<felt252, User>,
        artist_signed_agreement: Map::<ContractAddress, bool>,
        // #[substorage(v0)]
    // account: AccountComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        // #[flat]
        // AccountEvent: AccountComponent::Event,
        CreatedAccount: CreatedAccount,
        UpdatedAgreement: UpdatedAgreement,
        AgreementSigned: AgreementSigned,
        WhitelistedSignerUpdated: WhitelistedSignerUpdated,
        PaymentTokenUpdated: PaymentTokenUpdated,
    }


    #[derive(Drop, starknet::Event)]
    struct CreatedAccount {
        id: u32,
        address: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct UpdatedAgreement {
        updater: ContractAddress,
        time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AgreementSigned {
        signer: ContractAddress,
        time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WhitelistedSignerUpdated {
        new_signer: ContractAddress,
        time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentTokenUpdated {
        token_address: ContractAddress,
        time: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        _owner: ContractAddress,
        payment_token: ContractAddress,
        whitelisted_signer: ContractAddress,
        agreement_uri: ByteArray
    ) {
        self.owner.write(_owner);
        self.payment_token.write(payment_token);
        self.whitelisted_signer.write(whitelisted_signer);
        self.agreement_uri.write(agreement_uri);
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

            self
                .emit(
                    CreatedAccount { id: self.account_count.read() + 1, address: account_address }
                );

            account_address
        }

        fn sign_agreement(ref self: ContractState) {
            let caller = get_caller_address();
            let artist_signed_agreement = self.check_artist_signed_agreement(caller);
            assert(!artist_signed_agreement, 'AGREEMENT ALREADY SIGNED');
            self.artist_signed_agreement.entry(caller).write(true);
            self.emit(AgreementSigned { signer: caller, time: get_block_timestamp(), })
        }

        ///@notice Function triggered by client after payment is received for nft on the backend
        /// @notice A whitelisted signer is an account that triggers smart contract to complete nft transaction
        /// Whitelisted account should be implemented on the backend.
        /// Access is restricted to whitelisted signer for security
        /// Only one payment token is available (team can add more if they deem it needful)
        fn complete_nft_transaction(
            ref self: ContractState,
            nft_address: ContractAddress,
            buyer: ContractAddress,
            token_id: u256,
            amount: u256
        ) {
            let caller = get_caller_address();
            let nft_owner = IERC721Dispatcher { contract_address: nft_address }.owner_of(token_id);

            assert(caller == self.whitelisted_signer.read(), 'UNAUTHORIZED CALLER');

            let artist_royalty = self.perc(amount);
            let data = array![];

            IERC721Dispatcher { contract_address: nft_address }
                .safe_transfer_from(nft_owner, buyer, token_id, data.span());
            IERC20Dispatcher { contract_address: self.payment_token.read() }
                .transfer(nft_owner, artist_royalty);
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


        fn update_whitelisted_signer(ref self: ContractState, new_signer: ContractAddress) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'NOT OWNER');
            assert(new_signer.is_non_zero(), 'INVALID ADDRESS');
            self.whitelisted_signer.write(new_signer);
            self.emit(WhitelistedSignerUpdated { new_signer, time: get_block_timestamp(), });
        }

        fn update_payment_token(ref self: ContractState, token_address: ContractAddress) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'NOT OWNER');
            assert(token_address.is_non_zero(), 'INVALID ADDRESS');
            self.payment_token.write(token_address);
            self.emit(PaymentTokenUpdated { token_address, time: get_block_timestamp(), });
        }

        fn update_agreement_uri(ref self: ContractState, agreement_uri: ByteArray) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'NOT OWNER');
            self.agreement_uri.write(agreement_uri);
            self.emit(UpdatedAgreement { updater: caller, time: get_block_timestamp(), })
        }

        fn withdraw(ref self: ContractState, token: ContractAddress, recipient: ContractAddress, amount: u256) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'NOT OWNER');
            assert(recipient.is_non_zero(), 'INVALID RECIPIENT');
            assert(amount > 0, 'INVALID AMOUNT');
            let success = IERC20Dispatcher { contract_address: token }.transfer(recipient, amount);
            assert(success, 'WITHDRAW FAIL!');
        }


        fn check_artist_signed_agreement(self: @ContractState, artist: ContractAddress) -> bool {
            self.artist_signed_agreement.entry(artist).read()
        }

        fn get_account_owner_details(self: @ContractState, email: felt252) -> User {
            self.users.read(email)
        }

        fn get_account_count(self: @ContractState) -> u32 {
            self.account_count.read()
        }

        fn get_payment_token_address(self: @ContractState) -> ContractAddress {
            self.payment_token.read()
        }

        fn get_whitelisted_signer(self: @ContractState) -> ContractAddress {
            self.whitelisted_signer.read()
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

    #[generate_trait]
    impl Private of PrivateTrait {
        fn perc(self: @ContractState, amount: u256) -> u256 {
            let artist_royalty: u256 = (amount * 70) / 100;
            artist_royalty
        }
    }
}
