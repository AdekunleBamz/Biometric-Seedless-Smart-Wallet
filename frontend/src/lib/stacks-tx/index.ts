import { StacksTestnet, StacksMainnet } from '@stacks/network';
import {
    AnchorMode,
    PostConditionMode,
    makeContractCall,
    broadcastTransaction,
    makeStandardSTXPostCondition,
    FungibleConditionCode,
} from '@stacks/transactions';

export const getNetwork = (isMainnet: boolean = false) => {
    return isMainnet ? new StacksMainnet() : new StacksTestnet();
};
