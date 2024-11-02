// SPDX-License-Identifier: MIT
pub use starknet::{
    ContractAddress, class_hash::ClassHash, syscalls::deploy_syscall, SyscallResultTrait
};

#[starknet::interface]
pub trait ICommunityFactory<TContractState> {
    fn deploy_community_nft(
        ref self: TContractState, pauser: ContractAddress, minter: ContractAddress, name: ByteArray, symbol: ByteArray, salt: felt252
    ) -> ContractAddress;
}

#[starknet::component]
pub mod CommunityNftFactory {
    use super::ICommunityFactory;
    use starknet::{
        ContractAddress, class_hash::ClassHash, syscalls::deploy_syscall, SyscallResultTrait,
        storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess,}
    };
    use core::traits::{TryInto, Into};

    const COMMUNITY_NFT_CLASS_HASH: felt252 =
        0xdb8e966fd661153e22cd588ad816605900a06569edc47e2adcc629619b2b31;

    // storage
    #[storage]
    struct Storage {
        community_count: u32,
        communities: Map::<u32, ContractAddress>,
    }

    #[embeddable_as(Tickets)]
    impl CommunityFactoryImpl<
        TContractState, +HasComponent<TContractState>
    > of ICommunityFactory<ComponentState<TContractState>> {
        fn deploy_community_nft(
            ref self: ComponentState<TContractState>,
            pauser: ContractAddress,
            minter: ContractAddress,
            name: ByteArray, 
            symbol: ByteArray, 
            salt: felt252
        ) -> ContractAddress {

            let _community_count = self.community_count.read();

            // formatting constructor arguments
            let mut constructor_calldata: Array<felt252> = array![pauser.into(), minter.into(), name, symbol];
            // deploying the contract
            let class_hash: ClassHash = COMMUNITY_NFT_CLASS_HASH.try_into().unwrap();
            let result = deploy_syscall(class_hash, salt, constructor_calldata.span(), true);
            let (nft_address, _) = result.unwrap_syscall();

            self.community_count.write(_community_count + 1);

            self.communities.write(_community_count + 1, nft_address);

            nft_address
        }
    }
}
