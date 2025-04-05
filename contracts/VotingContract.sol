// contracts/VotingContract.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VotingContract {
    struct Scheme {
        uint256 id;
        string name;
        string description;
        bool active;
    }
    
    struct Vote {
        address voter;
        uint256 schemeId;
        bool vote;
        bool exists;
    }
    
    struct Delegation {
        address delegator;
        address delegatee;
        uint256 schemeId;
    }
    
    mapping(uint256 => Scheme) public schemes;
    mapping(address => mapping(uint256 => Vote)) public votes;
    mapping(address => mapping(uint256 => address)) public delegations;
    mapping(uint256 => address[]) public schemeVoters;
    
    uint256 public schemeCount = 0;
    address public admin;
    
    event SchemeCreated(uint256 id, string name, string description);
    event VoteCast(address indexed voter, uint256 indexed schemeId, bool vote);
    event DelegationSet(address indexed delegator, address indexed delegatee, uint256 indexed schemeId);
    
    constructor() {
        admin = msg.sender;
    }
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this function");
        _;
    }
    
    function createScheme(string memory _name, string memory _description) public onlyAdmin returns (uint256) {
        schemeCount++;
        schemes[schemeCount] = Scheme(schemeCount, _name, _description, true);
        emit SchemeCreated(schemeCount, _name, _description);
        return schemeCount;
    }
    
    function castVote(uint256 _schemeId, bool _vote) public {
        require(schemes[_schemeId].active, "Scheme is not active");
        require(!votes[msg.sender][_schemeId].exists, "You have already voted");
        
        // If the voter has delegated their vote, they cannot vote
        require(delegations[msg.sender][_schemeId] == address(0), "You have delegated your vote");
        
        votes[msg.sender][_schemeId] = Vote(msg.sender, _schemeId, _vote, true);
        schemeVoters[_schemeId].push(msg.sender);
        
        emit VoteCast(msg.sender, _schemeId, _vote);
    }
    
    function delegate(address _delegatee, uint256 _schemeId) public {
        require(schemes[_schemeId].active, "Scheme is not active");
        require(!votes[msg.sender][_schemeId].exists, "You have already voted");
        require(_delegatee != msg.sender, "Cannot delegate to yourself");
        
        // Check for circular delegation
        address currentDelegatee = _delegatee;
        while (currentDelegatee != address(0)) {
            require(currentDelegatee != msg.sender, "Circular delegation not allowed");
            currentDelegatee = delegations[currentDelegatee][_schemeId];
        }
        
        delegations[msg.sender][_schemeId] = _delegatee;
        emit DelegationSet(msg.sender, _delegatee, _schemeId);
    }
    
    function getVoteCount(uint256 _schemeId) public view returns (uint256 trueVotes, uint256 falseVotes) {
        for (uint i = 0; i < schemeVoters[_schemeId].length; i++) {
            address voter = schemeVoters[_schemeId][i];
            if (votes[voter][_schemeId].vote) {
                trueVotes++;
            } else {
                falseVotes++;
            }
        }
    }
    
    function getVoterWeight(address _voter, uint256 _schemeId) public view returns (uint256) {
        uint256 weight = 1;
        for (uint i = 0; i < schemeVoters[_schemeId].length; i++) {
            address potentialDelegator = schemeVoters[_schemeId][i];
            if (delegations[potentialDelegator][_schemeId] == _voter) {
                weight++;
            }
        }
        return weight;
    }
}
