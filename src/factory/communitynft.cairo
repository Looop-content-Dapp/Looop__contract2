// SPDX-License-Identifier: MIT
pub use starknet::{
    ContractAddress, class_hash::ClassHash, syscalls::deploy_syscall, SyscallResultTrait
};

#[starknet::interface]
pub trait ITribesFactory<TContractState> {
    fn deploy_tribes_nft(
        ref self: TContractState, pauser: ContractAddress, minter: ContractAddress, name: ByteArray, symbol: ByteArray, salt: felt252
    ) -> ContractAddress;
}

#[starknet::component]
pub mod TribesNftFactory {
    use super::ITribesFactory;
    use starknet::{
        ContractAddress, class_hash::ClassHash, syscalls::deploy_syscall, SyscallResultTrait,
        storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess,}
    };
    use core::traits::{TryInto, Into};

    const TRIBES_NFT_CLASS_HASH: felt252 =
        0xdb8e966fd661153e22cd588ad816605900a06569edc47e2adcc629619b2b31;

    // storage
    #[storage]
    struct Storage {
        tribes_count: u32,
        tribes: Map::<u32, ContractAddress>,
    }

    #[embeddable_as(Tickets)]
    impl TribesFactoryImpl<
        TContractState, +HasComponent<TContractState>
    > of ITribesFactory<ComponentState<TContractState>> {
        fn deploy_tribes_nft(
            ref self: ComponentState<TContractState>,
            pauser: ContractAddress,
            minter: ContractAddress,
            name: ByteArray, 
            symbol: ByteArray, 
            salt: felt252
        ) -> ContractAddress {

            let _tribes_count = self.tribes_count.read();

            // formatting constructor arguments
            let mut constructor_calldata: Array<felt252> = array![pauser.into(), minter.into(), name, symbol];
            // deploying the contract
            let class_hash: ClassHash = TRIBES_NFT_CLASS_HASH.try_into().unwrap();
            let result = deploy_syscall(class_hash, salt, constructor_calldata.span(), true);
            let (nft_address, _) = result.unwrap_syscall();

            self.tribes_count.write(_tribes_count + 1);

            self.tribes.write(_tribes_count + 1, nft_address);

            nft_address
        }
    }
}
