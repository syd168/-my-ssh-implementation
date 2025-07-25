#!/bin/bash

# SSH通信项目 - 阶段五测试脚本
# 测试SSH消息格式功能

echo "========================================"
echo "SSH Communication Project - Stage 5 Test"
echo "Testing SSH Packet Format"
echo "========================================"

# 检查是否已编译
if [ ! -f "build/test_packet" ]; then
    echo "Building project..."
    make all
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to build project"
        exit 1
    fi
fi

# 确保可执行文件有执行权限
chmod +x build/test_packet

# 测试SSH消息格式功能
echo ""
echo "Test: SSH Packet Format Implementation"
echo "======================================"

# 编译SSH消息格式测试程序
echo "Compiling SSH packet test program..."
make test-packet
if [ $? -eq 0 ]; then
    echo "✓ SSH packet test program compiled successfully"
else
    echo "✗ Failed to compile SSH packet test program"
    exit 1
fi

# 运行SSH消息格式测试
echo ""
echo "Running SSH packet format test..."
if [ -f "build/test_packet" ]; then
    ./build/test_packet
    if [ $? -eq 0 ]; then
        echo "✓ SSH packet format test passed"
    else
        echo "✗ SSH packet format test failed"
        exit 1
    fi
else
    echo "✗ SSH packet test program not found"
    exit 1
fi

echo ""
echo "Stage 5 Testing Complete"
echo "========================"
echo "1. SSH packet format implementation verified"
echo "2. Packet creation, serialization and parsing tested"
echo "3. Message type handling validated"
echo ""
echo "Next steps:"
echo "- Review the code in src/protocol/ssh_packet.c"
echo "- Consider implementing user authentication mechanisms"
echo "- Plan for channel management functionality"
#!/bin/bash

# SSH通信项目 - 阶段五测试脚本
# 测试SSH消息格式功能

echo "========================================"
echo "SSH Communication Project - Stage 5 Test"
echo "Testing SSH Packet Format"
echo "========================================"

# 检查是否已编译
if [ ! -f "build/test_packet" ]; then
    echo "Building project..."
    make all
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to build project"
        exit 1
    fi
fi

# 测试SSH消息格式功能
echo ""
echo "Test: SSH Packet Format Implementation"
echo "======================================"

# 编译SSH消息格式测试程序
echo "Compiling SSH packet test program..."
make test-packet
if [ $? -eq 0 ]; then
    echo "✓ SSH packet test program compiled successfully"
else
    echo "✗ Failed to compile SSH packet test program"
    exit 1
fi

# 运行SSH消息格式测试
echo ""
echo "Running SSH packet format test..."
if [ -f "build/test_packet" ]; then
    ./build/test_packet
    if [ $? -eq 0 ]; then
        echo "✓ SSH packet format test passed"
    else
        echo "✗ SSH packet format test failed"
        exit 1
    fi
else
    echo "✗ SSH packet test program not found"
    exit 1
fi

echo ""
echo "Stage 5 Testing Complete"
echo "========================"
echo "1. SSH packet format implementation verified"
echo "2. Packet creation, serialization and parsing tested"
echo "3. Message type handling validated"
echo ""
echo "Next steps:"
echo "- Review the code in src/protocol/ssh_packet.c"
echo "- Consider implementing user authentication mechanisms"
echo "- Plan for channel management functionality"