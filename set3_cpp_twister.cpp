#include <iostream>
#include <random>

int main() {
    std::mt19937 mt(1337);  // Seed
    for (int i = 0; i < 9000; ++i) {
        std::cout << mt() << std::endl;
    }
    return 0;
}

// g++ set3_cpp_twister.cpp -o set3_cpp_twister