#### 1. struct重定义
原因是不同的类中多次包含了含有结构体的头文件
#### 2. tsharkManager中正确初始化tsharkDatabase的对象指针
```c++
storage = std::make_shared<TsharkDatabase>("temp.db");
```

