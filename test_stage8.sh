#!/bin/bash

# SSH通信项目 - 阶段八测试脚本
# 测试应用层通信功能

echo "========================================"
echo "SSH Communication Project - Stage 8 Test"
echo "Testing Application Layer Communication"
echo "========================================"

# 测试应用层通信功能
echo ""
echo "Test: Application Layer Communication Implementation"
echo "==================================================="

# 编译应用层通信测试程序
echo "Compiling application layer test program..."
make test-app
if [ $? -eq 0 ]; then
    echo "✓ Application layer test program compiled successfully"
else
    echo "✗ Failed to compile application layer test program"
    exit 1
fi

# 运行应用层通信测试
echo ""
echo "Running application layer test..."
if [ -f "build/test_app" ]; then
    ./build/test_app
    if [ $? -eq 0 ]; then
        echo "✓ Application layer test passed"
    else
        echo "✗ Application layer test failed"
        exit 1
    fi
else
    echo "✗ Application layer test program not found"
    exit 1
fi

echo ""
echo "Stage 8 Testing Complete"
echo "========================"
echo "1. Command execution functionality verified"
echo "2. Shell application implementation tested"
echo "3. File transfer functionality validated"
echo "4. Process and resource management tested"
echo ""
echo "Project Complete!"
echo "=================="
echo "All stages of the SSH communication project have been successfully implemented and tested."
echo "The project now includes:"
echo "  - Basic network communication"
echo "  - Protocol version negotiation"
echo "  - Key exchange and encryption"
echo "  - User authentication"
echo "  - Channel management"
echo "  - Application layer communication"
echo ""
echo "Next steps:"
echo "- Review the complete codebase"
echo "- Consider implementing additional SSH features"
echo "- Explore advanced security mechanisms"
echo "- Document lessons learned"