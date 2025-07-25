#!/bin/bash

# SSH通信项目 - 阶段六测试脚本
# 测试用户认证功能

echo "========================================"
echo "SSH Communication Project - Stage 6 Test"
echo "Testing User Authentication"
echo "========================================"

# 检查是否已编译
if [ ! -f "build/test_auth" ]; then
    echo "Building project..."
    make all
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to build project"
        exit 1
    fi
fi

# 测试用户认证功能
echo ""
echo "Test: User Authentication Implementation"
echo "========================================"

# 编译用户认证测试程序
echo "Compiling user authentication test program..."
make test-auth
if [ $? -eq 0 ]; then
    echo "✓ User authentication test program compiled successfully"
else
    echo "✗ Failed to compile user authentication test program"
    exit 1
fi

# 运行用户认证测试
echo ""
echo "Running user authentication test..."
if [ -f "build/test_auth" ]; then
    ./build/test_auth
    if [ $? -eq 0 ]; then
        echo "✓ User authentication test passed"
    else
        echo "✗ User authentication test failed"
        exit 1
    fi
else
    echo "✗ User authentication test program not found"
    exit 1
fi

echo ""
echo "Stage 6 Testing Complete"
echo "========================"
echo "1. User authentication implementation verified"
echo "2. Authentication request creation and parsing tested"
echo "3. Credential verification validated"
echo "4. Success/failure message handling tested"
echo ""
echo "Next steps:"
echo "- Review the code in src/protocol/auth.c"
echo "- Consider implementing public key authentication"
echo "- Plan for secure channel establishment"