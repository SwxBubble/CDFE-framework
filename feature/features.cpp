
#include "feature/features.h"
#include "chunk/chunk.h"
#include "utils/gear.h"
#include "utils/rabin.cpp"
#include <algorithm>
#include <cstdint>
#include <queue>

// 引入必要的头文件
//#include "utils/sha1.h" // 使用现有的 SHA1 工具
#include <openssl/sha.h>
#include <glog/logging.h>
#include <cmath>

#include <iostream> // 必须包含，用于 std::cout
#include <iomanip>  // 必须包含，用于 std::setw, std::setprecision


/*
//rabin
#include "feature/features.h"
#include "chunk/chunk.h"
#include "utils/gear.h"
#include "utils/rabin.cpp" 
#include <algorithm>
#include <cstdint>
#include <queue>
#include <cmath>
#include <cstring>
#include <limits>
#include <glog/logging.h>
#include <iostream> 
#include <iomanip>*/
namespace Delta {
Feature FinesseFeature::operator()(std::shared_ptr<Chunk> chunk) {
  int sub_chunk_length = chunk->len() / (sf_subf_ * sf_cnt_);
  uint8_t *content = chunk->buf();
  std::vector<uint64_t> sub_features(sf_cnt_ * sf_subf_, 0);
  std::vector<uint64_t> super_features(sf_cnt_, 0);

  // calculate sub features.
  for (int i = 0; i < sub_features.size(); i++) {
    rabin_t rabin_ctx;
    rabin_init(&rabin_ctx);
    for (int j = 0; j < sub_chunk_length; j++) {
      rabin_append(&rabin_ctx, content[j]);
      sub_features[i] = std::max(rabin_ctx.digest, sub_features[i]);
    }
    content += sub_chunk_length;
  }

  // group the sub features into super features.
  for (int i = 0; i < sub_features.size(); i += sf_subf_) {
    std::sort(sub_features.begin() + i, sub_features.begin() + i + sf_subf_);
  }
  for (int i = 0; i < sf_cnt_; i++) {
    rabin_t rabin_ctx;
    rabin_init(&rabin_ctx);
    for (int j = 0; j < sf_subf_; j++) {
      auto sub_feature = sub_features[sf_subf_ * i + j];
      auto data_ptr = (uint8_t *)&sub_feature;
      for (int k = 0; k < 8; k++) {
        rabin_append(&rabin_ctx, data_ptr[k]);
      }
    }
    super_features[i] = rabin_ctx.digest;
  }
  return super_features;
}

static uint32_t M[] = {
    0x5b49898a, 0xe4f94e27, 0x95f658b2, 0x8f9c99fc, 0xeba8d4d8, 0xba2c8e92,
    0xa868aeb4, 0xd767df82, 0x843606a4, 0xc1e70129, 0x32d9d1b0, 0xeb91e53c,
};

static uint32_t A[] = {
    0xff4be8c,  0x6f485986, 0x12843ff,  0x5b47dc4d, 0x7faa9b8a, 0xd547b8ba,
    0xf9979921, 0x4f5400da, 0x725f79a9, 0x3c9321ac, 0x32716d,   0x3f5adf5d,
};

Feature NTransformFeature::operator()(std::shared_ptr<Chunk> chunk) {
  int features_num = sf_cnt_ * sf_subf_;
  std::vector<uint32_t> sub_features(features_num, 0);
  std::vector<uint64_t> super_features(sf_cnt_, 0);

  int chunk_length = chunk->len();
  uint8_t *content = chunk->buf();
  uint64_t finger_print = 0;
  // calculate sub features.
  for (int i = 0; i < chunk_length; i++) {
    finger_print = (finger_print << 1) + GEAR_TABLE[content[i]];
    for (int j = 0; j < features_num; j++) {
      const uint32_t transform = (M[j] * finger_print + A[j]);
      // we need to guarantee that when sub_features[i] is not inited,
      // always set its value
      if (sub_features[j] >= transform || 0 == sub_features[j])
        sub_features[j] = transform;
    }
  }

  // group sub features into super features.
  auto hash_buf = (const uint8_t *const)(sub_features.data());
  for (int i = 0; i < sf_cnt_; i++) {
    uint64_t hash_value = 0;
    auto this_hash_buf = hash_buf + i * sf_subf_ * sizeof(uint32_t);
    for (int j = 0; j < sf_subf_ * sizeof(uint32_t); j++) {
      hash_value = (hash_value << 1) + GEAR_TABLE[this_hash_buf[j]];
    }
    super_features[i] = hash_value;
  }
  return super_features;
}

Feature OdessFeature::operator()(std::shared_ptr<Chunk> chunk) {
  int features_num = sf_cnt_ * sf_subf_;
  std::vector<uint32_t> sub_features(features_num, 0);
  std::vector<uint64_t> super_features(sf_cnt_, 0);

  int chunk_length = chunk->len();
  uint8_t *content = chunk->buf();
  uint64_t finger_print = 0;
  // calculate sub features.
  for (int i = 0; i < chunk_length; i++) {
    finger_print = (finger_print << 1) + GEAR_TABLE[content[i]];
    if ((finger_print & mask_) == 0) {
      for (int j = 0; j < features_num; j++) {
        const uint32_t transform = (M[j] * finger_print + A[j]);
        // we need to guarantee that when sub_features[i] is not inited,
        // always set its value
        if (sub_features[j] >= transform || 0 == sub_features[j])
          sub_features[j] = transform;
      }
    }
  }

  // group sub features into super features.
  auto hash_buf = (const uint8_t *const)(sub_features.data());
  for (int i = 0; i < sf_cnt_; i++) {
    uint64_t hash_value = 0;
    auto this_hash_buf = hash_buf + i * sf_subf_ * sizeof(uint32_t);
    for (int j = 0; j < sf_subf_ * sizeof(uint32_t); j++) {
      hash_value = (hash_value << 1) + GEAR_TABLE[this_hash_buf[j]];
    }
    super_features[i] = hash_value;
  }
  return super_features;
}

Feature OdessSubfeatures::operator()(std::shared_ptr<Chunk> chunk) {
  int mask_ = default_odess_mask;
  int features_num = 12;
  std::vector<uint64_t> sub_features(features_num, 0);

  int chunk_length = chunk->len();
  uint8_t *content = chunk->buf();
  uint32_t finger_print = 0;
  // calculate sub features.
  for (int i = 0; i < chunk_length; i++) {
    finger_print = (finger_print << 1) + GEAR_TABLE[content[i]];
    if ((finger_print & mask_) == 0) {
      for (int j = 0; j < features_num; j++) {
        const uint64_t transform = (M[j] * finger_print + A[j]);
        // we need to guarantee that when sub_features[i] is not inited,
        // always set its value
        if (sub_features[j] >= transform || 0 == sub_features[j])
          sub_features[j] = transform;
      }
    }
  }

  return sub_features;
}

Feature PalantirFeature::operator()(std::shared_ptr<Chunk> chunk) {
  auto sub_features = std::get<std::vector<uint64_t>>(get_sub_features_(chunk));
  std::vector<std::vector<uint64_t>> results;

  auto group = [&](int sf_cnt, int sf_subf) -> std::vector<uint64_t> {
    std::vector<uint64_t> super_features(sf_cnt, 0);
    auto hash_buf = (const uint8_t *const)(sub_features.data());
    for (int i = 0; i < sf_cnt; i++) {
      uint64_t hash_value = 0;
      auto this_hash_buf = hash_buf + i * sf_subf * sizeof(uint64_t);
      for (int j = 4; j < sf_subf * sizeof(uint64_t); j++) {
        hash_value = (hash_value << 1) + GEAR_TABLE[this_hash_buf[j]];
      }
      super_features[i] = hash_value;
    }
    return super_features;
  };

  results.push_back(group(3, 4));
  results.push_back(group(4, 3));
  results.push_back(group(6, 2));
  return results;
}


/*CDFE*/
// Algorithm 2: 寻找切分点
// fingerprints: 预计算好的指纹数组
// start_pos: 上一个切分点的位置
// min_pos, max_pos: 当前搜索的绝对范围边界
// avg_pos: 期望的切分点位置 (start_pos + a)
// 辅助函数：将 SHA1 摘要转换为十六进制字符串，方便日志打印
// ================= CDFE + MinHash 实现 原版一 子块sha256+n_trans+超特=================

/*
int CDFEFeature::get_breakpoint(const std::vector<uint64_t>& fingerprints, 
                                int start_pos, int min_pos, int max_pos, 
                                int avg_pos, int divisor) {
    int distance = 0;
    int chunk_len = fingerprints.size();

    while (true) {
        int l_window = avg_pos - distance;
        int r_window = avg_pos + distance;
        
        bool l_valid = (l_window > min_pos && l_window < max_pos && l_window < chunk_len);
        bool r_valid = (r_window < max_pos && r_window > min_pos && r_window < chunk_len);

        if (!l_valid && !r_valid) break;

        // 优先检查左侧
        if (l_valid) {
            if (fingerprints[l_window] % divisor == 0) return l_window;
        }
        // 检查右侧
        if (r_valid && r_window != l_window) {
            if (fingerprints[r_window] % divisor == 0) return r_window;
        }

        distance++;
    }
    return -1;
}
*/

// ================= 新增：析构函数实现 (打印统计信息) =================
/*
CDFEFeature::~CDFEFeature() {
    // 这段代码会在程序结束时自动执行
    std::cout << "\n================ CDFE Algorithm Statistics ================" << std::endl;
    std::cout << "Total Sub-chunks Generated: " << total_sub_chunks_ << std::endl;
    
    size_t total_cuts = d1_cuts_ + d2_cuts_ + force_cuts_;
    
    if (total_cuts > 0) {
        // 定义一个简单的打印 lambda 方便格式化
        auto print_stat = [&](const char* name, size_t count) {
            double percent = (double)count / total_cuts * 100.0;
            std::cout << std::left << std::setw(25) << name 
                      << ": " << std::setw(8) << count 
                      << "(" << std::fixed << std::setprecision(2) << percent << "%)" 
                      << std::endl;
        };

        print_stat("D1 Cuts (Primary)", d1_cuts_);
        print_stat("D2 Cuts (Secondary)", d2_cuts_);
        print_stat("Force Cuts (Max Len)", force_cuts_);
    } else {
        std::cout << "No cuts recorded. (Maybe dataset is too small?)" << std::endl;
    }
    std::cout << "===========================================================\n" << std::endl;
}


Feature CDFEFeature::operator()(std::shared_ptr<Chunk> chunk) {
    int len = chunk->len();
    uint8_t* buf = chunk->buf();
    
    // 1. 预计算 Rabin 指纹 (用于 CDFE 切分)
    std::vector<uint64_t> fingerprints(len, 0);
    rabin_t rabin_ctx;
    rabin_init(&rabin_ctx);
    for (int i = 0; i < len; ++i) {
        rabin_slide(&rabin_ctx, buf[i]);
        fingerprints[i] = rabin_ctx.digest;
    }

    std::vector<int> breakpoint_list;
    breakpoint_list.push_back(0);

    // 2. 执行 CDFE 切分
    int last_bp = 0;
    int curr_min = last_bp + L1_;
    int curr_max = last_bp + L2_;
    int curr_avg = last_bp + a_;

    while (curr_max < len - 1) {
        int bp = -1;
        // D1 -> D2 -> Force Cut 策略
        bp = get_breakpoint(fingerprints, last_bp, curr_min, curr_max, curr_avg, D1_);
        // if (bp == -1) {
        //     bp = get_breakpoint(fingerprints, last_bp, curr_min, curr_max, curr_avg, D2_);
        // }
        // if (bp == -1) {
        //     bp = curr_max;
        // }

        
        //在原来打印的基础上输出CDFE一共累计分割了多少个子块，有多少个是D1分割的，有多少个是D2分割的，以及有多少个是D1、D2没有查找到分割点以最大边界分割的
        //==================================================

        if (bp != -1) {
            d1_cuts_++; // [统计] D1 命中
        } 
        else {
            // 尝试 D2
            bp = get_breakpoint(fingerprints, last_bp, curr_min, curr_max, curr_avg, D2_);
            if (bp != -1) {
                d2_cuts_++; // [统计] D2 命中
            }
        }

        // 强制切分
        if (bp == -1) {
            bp = curr_max;
            force_cuts_++; // [统计] 强制切分
        }

        //==================================================
        
        breakpoint_list.push_back(bp);
        last_bp = bp;
        curr_min = last_bp + L1_;
        curr_max = last_bp + L2_;
        curr_avg = last_bp + a_;
    }
    breakpoint_list.push_back(len - 1);

    //==================================================
    // [统计] 累计总子块数
    // 当前 Chunk 被切分成了 (breakpoint_list.size() - 1) 个子块
    total_sub_chunks_ += (breakpoint_list.size() - 1);
    //==================================================

    // 3. 准备 MinHash 容器
    int total_features = sf_cnt_ * sf_subf_; // 通常是 12
    // 初始化为最大值，准备取 min
    std::vector<uint64_t> min_hash_values(total_features, std::numeric_limits<uint64_t>::max());

    // 4. 遍历所有子块 (CDFE Sub-chunks)
    for (size_t i = 1; i < breakpoint_list.size(); ++i) {
        int begin = breakpoint_list[i - 1];
        int end = breakpoint_list[i];
        int sub_len = end - begin;
        
        if (sub_len <= 0) continue;

        // 4.1 计算子块的 SHA256 哈希
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(buf + begin, sub_len, hash);
        
        // 将前8字节转为 uint64 作为该子块的原始特征值 h
        uint64_t sub_chunk_hash = 0;
        memcpy(&sub_chunk_hash, hash, sizeof(uint64_t));

        // 4.2 对每个子块哈希应用 N 个线性变换，并更新全局最小值
        for (int j = 0; j < total_features; j++) {
            // 线性变换： h_j = M[j] * h + A[j]
            // 使用 features.cpp 中预定义的 M 和 A 数组
            uint64_t transformed = (uint64_t)M[j] * sub_chunk_hash + (uint64_t)A[j];
            
            // MinHash 核心：保留最小的哈希值
            if (transformed < min_hash_values[j]) {
                min_hash_values[j] = transformed;
            }
        }
    }

    // 5. 将 MinHash 结果分组为超级特征 (Super Features)
    // 参考 NTransformFeature 的做法，使用 Gear Hash 进行组合
    
    std::vector<uint64_t> super_features(sf_cnt_, 0);
    auto hash_buf = (const uint8_t *const)(min_hash_values.data());

    for (int i = 0; i < sf_cnt_; i++) {
        uint64_t group_hash = 0;
        // 计算这一组的起始位置
        auto this_group_buf = hash_buf + i * sf_subf_ * sizeof(uint64_t);
        
        // 对这组内的所有字节进行 Gear Hash 滚动
        for (int j = 0; j < sf_subf_ * sizeof(uint64_t); j++) {
            group_hash = (group_hash << 1) + GEAR_TABLE[this_group_buf[j]];
        }
        super_features[i] = group_hash;
    }

    LOG(INFO) << "<<< CDFE-MinHash: Processed " << chunk->id() 
              << ". Sub-chunks: " << (breakpoint_list.size() - 1)
              << ". Generated " << super_features.size() << " SuperFeatures.";

    return super_features;
}
*/


//=================================第二版 rabin代替sha256 对每个子块取最大和最小值作为特征========================================================================

// 复用 NTransform 的线性变换参数
// 这里的 M 和 A 是随机生成的线性变换系数，用于 MinHash
/*
static const uint64_t M2[] = {
    13365668979328220023ULL, 13709893977386121333ULL, 1025263749774676459ULL, 
    5398282306719875971ULL, 16892305315809796657ULL, 10793663765478440263ULL, 
    11032332732952579039ULL, 15993081977051413809ULL, 16309226875799974577ULL, 
    55633390234127027ULL, 11467633219323730769ULL, 17292323377727937743ULL
};
static const uint64_t A2[] = {
    8622746404747587009ULL, 11925345738670830953ULL, 1530932029953284353ULL, 
    17327323164923140509ULL, 13629237367672952973ULL, 12628450379204006637ULL, 
    5362932367293279509ULL, 1152932039239843353ULL, 12629323329248473523ULL, 
    12629323323948473523ULL, 1152932039239843353ULL, 13629237367672952973ULL
};

// ================= CDFE 析构函数 (统计报告) =================
CDFEFeature::~CDFEFeature() {
    std::cout << "\n================ CDFE++ (Robust) Algorithm Statistics ================" << std::endl;
    std::cout << "Total Sub-chunks Generated: " << total_sub_chunks_ << std::endl;
    
    size_t total_cuts = d1_cuts_ + d2_cuts_ + force_cuts_;
    
    if (total_cuts > 0) {
        auto print_stat = [&](const char* name, size_t count) {
            double percent = (double)count / total_cuts * 100.0;
            std::cout << std::left << std::setw(25) << name 
                      << ": " << std::setw(8) << count 
                      << "(" << std::fixed << std::setprecision(2) << percent << "%)" 
                      << std::endl;
        };

        print_stat("D1 Cuts (Primary)", d1_cuts_);
        print_stat("D2 Cuts (Secondary)", d2_cuts_);
        print_stat("Force Cuts (Max Len)", force_cuts_);
    }
    std::cout << "==================================================================\n" << std::endl;
}

// ================= CDFE get_breakpoint (双向搜索) =================
int CDFEFeature::get_breakpoint(const std::vector<uint64_t>& fingerprints, 
                                int start_pos, int min_pos, int max_pos, 
                                int avg_pos, int divisor) {
    int distance = 0;
    int chunk_len = fingerprints.size();

    while (true) {
        int l_window = avg_pos - distance;
        int r_window = avg_pos + distance;
        
        bool l_valid = (l_window > min_pos && l_window < max_pos && l_window < chunk_len);
        bool r_valid = (r_window < max_pos && r_window > min_pos && r_window < chunk_len);

        if (!l_valid && !r_valid) break;

        if (l_valid && (fingerprints[l_window] % divisor == 0)) return l_window;
        if (r_valid && r_window != l_window && (fingerprints[r_window] % divisor == 0)) return r_window;

        distance++;
    }
    return -1;
}

// ================= CDFE 主逻辑 (Improved for Robustness) =================
Feature CDFEFeature::operator()(std::shared_ptr<Chunk> chunk) {
    int len = chunk->len();
    uint8_t* buf = chunk->buf();
    
    // 1. 预计算 Rabin 指纹 (全局)
    std::vector<uint64_t> fingerprints(len, 0);
    rabin_t rabin_ctx;
    rabin_init(&rabin_ctx);
    for (int i = 0; i < len; ++i) {
        rabin_slide(&rabin_ctx, buf[i]);
        fingerprints[i] = rabin_ctx.digest;
    }

    std::vector<int> breakpoint_list;
    breakpoint_list.push_back(0);

    // 2. 执行 CDFE 切分
    int last_bp = 0;
    int curr_min = last_bp + L1_;
    int curr_max = last_bp + L2_;
    int curr_avg = last_bp + a_;

    while (curr_max < len - 1) {
        int bp = -1;
        bp = get_breakpoint(fingerprints, last_bp, curr_min, curr_max, curr_avg, D1_);
        if (bp != -1) {
            d1_cuts_++;
        } else {
            bp = get_breakpoint(fingerprints, last_bp, curr_min, curr_max, curr_avg, D2_);
            if (bp != -1) d2_cuts_++;
        }

        if (bp == -1) {
            bp = curr_max;
            force_cuts_++;
        }
        
        breakpoint_list.push_back(bp);
        last_bp = bp;
        curr_min = last_bp + L1_;
        curr_max = last_bp + L2_;
        curr_avg = last_bp + a_;
    }
    breakpoint_list.push_back(len - 1);
    total_sub_chunks_ += (breakpoint_list.size() - 1);

    // 3. 准备 MinHash 容器 (12 个变换)
    int total_features = sf_cnt_ * sf_subf_; // 3 * 4 = 12
    std::vector<uint64_t> min_hash_values(total_features, std::numeric_limits<uint64_t>::max());

    // 4. 【核心改进】遍历子块，提取 Robust 特征
    for (size_t i = 1; i < breakpoint_list.size(); ++i) {
        int begin = breakpoint_list[i - 1];
        int end = breakpoint_list[i];
        
        // 4.1 在子块内部寻找极值 (Local Extremes)
        // 这一步替代了之前的 SHA256。
        // 我们寻找子块内 Rabin 指纹的最小值和最大值。
        // 原理：即使子块内容被修改，只要修改没有覆盖到最小值所在的位置，最小值就不会变。
        
        uint64_t min_fp = std::numeric_limits<uint64_t>::max();
        uint64_t max_fp = std::numeric_limits<uint64_t>::min();

        // 遍历当前子块范围内的指纹
        for (int k = begin; k <= end && k < len; ++k) {
            if (fingerprints[k] < min_fp) min_fp = fingerprints[k];
            if (fingerprints[k] > max_fp) max_fp = fingerprints[k];
        }

        // 4.2 将提取到的特征 (Min 和 Max) 喂给 MinHash 计算器
        // 这样每个子块贡献 2 个特征，增加了密度
        uint64_t chunk_features[] = {min_fp, max_fp};

        for (uint64_t raw_feature : chunk_features) {
            for (int j = 0; j < total_features; j++) {
                // 线性变换
                uint64_t transformed = M2[j] * raw_feature + A2[j];
                // 更新全局最小值
                if (transformed < min_hash_values[j]) {
                    min_hash_values[j] = transformed;
                }
            }
        }
    }

    // 5. 将 MinHash 结果分组为 Super Features
    std::vector<uint64_t> super_features(sf_cnt_, 0);
    auto hash_buf = (const uint8_t *const)(min_hash_values.data());

    for (int i = 0; i < sf_cnt_; i++) {
        uint64_t group_hash = 0;
        auto this_group_buf = hash_buf + i * sf_subf_ * sizeof(uint64_t);
        for (int j = 0; j < sf_subf_ * sizeof(uint64_t); j++) {
            group_hash = (group_hash << 1) + GEAR_TABLE[this_group_buf[j]];
        }
        super_features[i] = group_hash;
    }

    return super_features;
}*/



//=====================第三版  用“局部（以 last_bp 为起点）Rabin 指纹”替代原先的全局预计算指纹===========================
// 复用 NTransform 的线性变换参数
// 这里的 M 和 A 是随机生成的线性变换系数，用于 MinHash
static const uint64_t M2[] = {
    13365668979328220023ULL, 13709893977386121333ULL, 1025263749774676459ULL, 
    5398282306719875971ULL, 16892305315809796657ULL, 10793663765478440263ULL, 
    11032332732952579039ULL, 15993081977051413809ULL, 16309226875799974577ULL, 
    55633390234127027ULL, 11467633219323730769ULL, 17292323377727937743ULL
};
static const uint64_t A2[] = {
    8622746404747587009ULL, 11925345738670830953ULL, 1530932029953284353ULL, 
    17327323164923140509ULL, 13629237367672952973ULL, 12628450379204006637ULL, 
    5362932367293279509ULL, 1152932039239843353ULL, 12629323329248473523ULL, 
    12629323323948473523ULL, 1152932039239843353ULL, 13629237367672952973ULL
};

// ================= CDFE 析构函数 (统计报告) =================
CDFEFeature::~CDFEFeature() {
    std::cout << "\n================ CDFE++ (Robust) Algorithm Statistics ================" << std::endl;
    std::cout << "Total Sub-chunks Generated: " << total_sub_chunks_ << std::endl;
    
    size_t total_cuts = d1_cuts_ + d2_cuts_ + force_cuts_;
    
    if (total_cuts > 0) {
        auto print_stat = [&](const char* name, size_t count) {
            double percent = (double)count / total_cuts * 100.0;
            std::cout << std::left << std::setw(25) << name 
                      << ": " << std::setw(8) << count 
                      << "(" << std::fixed << std::setprecision(2) << percent << "%)" 
                      << std::endl;
        };

        print_stat("D1 Cuts (Primary)", d1_cuts_);
        print_stat("D2 Cuts (Secondary)", d2_cuts_);
        print_stat("Force Cuts (Max Len)", force_cuts_);
    }
    std::cout << "==================================================================\n" << std::endl;
}

// ================= CDFE get_breakpoint (双向搜索) =================
// NOTE: MODIFIED: 现在该函数期望传入的是 "局部指纹数组 local_fps"
//       参数 semantics:
//         fingerprints -> local_fps (fingerprints[0] 对应 absolute pos = start_pos)
//         start_pos    -> offset (absolute position of local_fps[0])
int CDFEFeature::get_breakpoint(const std::vector<uint64_t>& fingerprints, 
                                int start_pos, int min_pos, int max_pos, 
                                int avg_pos, int divisor) {
    int distance = 0;
    int local_len = fingerprints.size();
    int offset = start_pos; // absolute position corresponding to fingerprints[0]

    while (true) {
        int l_window = avg_pos - distance;
        int r_window = avg_pos + distance;
        
        // NOTE: MODIFIED -> 使用包含边界的判断（>= / <=），避免忽略 min_pos/max_pos 本身
        bool l_valid = (l_window >= min_pos && l_window <= max_pos && l_window >= offset && l_window < offset + local_len);
        bool r_valid = (r_window <= max_pos && r_window >= min_pos && r_window >= offset && r_window < offset + local_len);

        if (!l_valid && !r_valid) break;

        if (l_valid) {
            int idx = l_window - offset;
            if (idx >= 0 && idx < local_len && (fingerprints[idx] % divisor == 0)) return l_window;
        }
        if (r_valid && r_window != l_window) {
            int idx = r_window - offset;
            if (idx >= 0 && idx < local_len && (fingerprints[idx] % divisor == 0)) return r_window;
        }

        distance++;
    }
    return -1;
}

// ================= CDFE get_breakpoint_gear (双向搜索, Gear-based) =================
// ADDED: 新增的 Gear 触发器。参数 semantics 类似 get_breakpoint，但
//       使用 (gear_fps[idx] & mask) == 0 作为触发条件。
int CDFEFeature::get_breakpoint_gear(const std::vector<uint64_t>& gear_fps,
                                     int start_pos, int min_pos, int max_pos, 
                                     int avg_pos, uint64_t mask) {
    int distance = 0;
    int local_len = (int)gear_fps.size();
    int offset = start_pos;

    while (true) {
        int l_window = avg_pos - distance;
        int r_window = avg_pos + distance;

        bool l_valid = (l_window >= min_pos && l_window <= max_pos && l_window >= offset && l_window < offset + local_len);
        bool r_valid = (r_window <= max_pos && r_window >= min_pos && r_window >= offset && r_window < offset + local_len);

        if (!l_valid && !r_valid) break;

        if (l_valid) {
            int idx = l_window - offset;
            if (idx >= 0 && idx < local_len && ((gear_fps[idx] & mask) == 0)) return l_window;
        }
        if (r_valid && r_window != l_window) {
            int idx = r_window - offset;
            if (idx >= 0 && idx < local_len && ((gear_fps[idx] & mask) == 0)) return r_window;
        }

        distance++;
    }
    return -1;
}


// ================= CDFE 主逻辑 (Improved for Robustness) =================

Feature CDFEFeature::operator()(std::shared_ptr<Chunk> chunk) {
    int len = chunk->len();
    uint8_t* buf = chunk->buf();
    
    // =========================
    // REMOVED: 原先全局预计算 Rabin 指纹 (fingerprints 全局数组)
    //         现在改为按 segment / subchunk 局部计算 Rabin 指纹 (local_fps)
    //         因为我们希望子块指纹仅由子块内部决定，避免上一个子块的前缀污染
    // =========================
    // std::vector<uint64_t> fingerprints(len, 0);
    // rabin_t rabin_ctx;
    // rabin_init(&rabin_ctx);
    // for (int i = 0; i < len; ++i) {
    //     rabin_slide(&rabin_ctx, buf[i]);
    //     fingerprints[i] = rabin_ctx.digest;
    // }


    std::vector<int> breakpoint_list;
    breakpoint_list.push_back(0);

    // 2. 执行 CDFE 切分
    int last_bp = 0;
    int curr_min = last_bp + L1_;
    int curr_max = last_bp + L2_;
    int curr_avg = last_bp + a_;

    while (curr_max < len - 1) {
        int bp = -1;

        // =========================
        // ADDED: 为当前待切段 [last_bp, curr_max] 计算局部指纹 local_fps
        //       local_fps[i - last_bp] 对应绝对位置 i 的 Rabin digest（从 last_bp 初始化）
        // =========================
        int seg_start = last_bp;
        int seg_end = std::min(len - 1, curr_max);
        int local_len = seg_end - seg_start + 1;
        std::vector<uint64_t> local_fps(local_len);

        rabin_t local_rabin;
        rabin_init(&local_rabin);
        for (int p = seg_start; p <= seg_end; ++p) {
            rabin_slide(&local_rabin, buf[p]);
            local_fps[p - seg_start] = local_rabin.digest;
        }

        // 使用局部指纹进行切点查找（先 D1，再 D2）
        bp = get_breakpoint(local_fps, seg_start, curr_min, curr_max, curr_avg, D1_);
        if (bp != -1) {
            d1_cuts_++;
        } else {
            bp = get_breakpoint(local_fps, seg_start, curr_min, curr_max, curr_avg, D2_);
            if (bp != -1) d2_cuts_++;
        }

        if (bp == -1) {
            bp = curr_max;
            force_cuts_++;
        }
        
        breakpoint_list.push_back(bp);
        last_bp = bp;
        curr_min = last_bp + L1_;
        curr_max = last_bp + L2_;
        curr_avg = last_bp + a_;
    }
    breakpoint_list.push_back(len - 1);
    total_sub_chunks_ += (breakpoint_list.size() - 1);

    // 3. 准备 MinHash 容器 (12 个变换)
    int total_features = sf_cnt_ * sf_subf_; // 3 * 4 = 12
    std::vector<uint64_t> min_hash_values(total_features, std::numeric_limits<uint64_t>::max());

    // 4. 【核心改进】遍历子块，提取 Robust 特征 
    // for (size_t i = 1; i < breakpoint_list.size(); ++i) {
    //     int begin = breakpoint_list[i - 1];
    //     int end = breakpoint_list[i];

    //     // =========================
    //     // MODIFIED: 不再直接读取全局 fingerprints，而是为每个子块单独计算局部指纹
    //     //           （确保子块特征仅由子块内部决定）
    //     // =========================
    //     int sub_start = begin;
    //     int sub_end = std::min(end, len - 1);
    //     int sub_len = sub_end - sub_start + 1;

    //     uint64_t min_fp = std::numeric_limits<uint64_t>::max();
    //     uint64_t max_fp = std::numeric_limits<uint64_t>::min();

    //     rabin_t sub_rabin;
    //     rabin_init(&sub_rabin);
    //     for (int p = sub_start; p <= sub_end; ++p) {
    //         rabin_slide(&sub_rabin, buf[p]);
    //         uint64_t v = sub_rabin.digest;
    //         if (v < min_fp) min_fp = v;
    //         if (v > max_fp) max_fp = v;
    //     }

    //     // 4.2 将提取到的特征 (Min 和 Max) 喂给 MinHash 计算器
    //     // 这样每个子块贡献 2 个特征，增加了密度
    //     uint64_t chunk_features[] = {min_fp, max_fp};

    //     for (uint64_t raw_feature : chunk_features) {
    //         for (int j = 0; j < total_features; j++) {
    //             // 线性变换
    //             uint64_t transformed = M2[j] * raw_feature + A2[j];
    //             // 更新全局最小值
    //             if (transformed < min_hash_values[j]) {
    //                 min_hash_values[j] = transformed;
    //             }
    //         }
    //     }
    // }


        // 4. 【核心改进】遍历子块，提取 Robust 特征
    for (size_t i = 1; i < breakpoint_list.size(); ++i) {
        int begin = breakpoint_list[i - 1];
        int end = breakpoint_list[i];

        // =========================
        // MODIFIED: 使用 top-K minima 替代原先的 (min, max)
        //           这里选择 K = 2，即取子块内最小的两个 Rabin 指纹作为特征
        //           优点：对局部修改更鲁棒（如果最小值被破坏，第二小值仍可能保留语义）
        // =========================
        int sub_start = begin;
        int sub_end = std::min(end, len - 1);
        int sub_len = sub_end - sub_start + 1;

        // Top-K minima 参数（当前固定为 2）
        const int K = 2;

        // 初始化 top-K minima 为最大值
        uint64_t min1 = std::numeric_limits<uint64_t>::max();
        uint64_t min2 = std::numeric_limits<uint64_t>::max();

        rabin_t sub_rabin;
        rabin_init(&sub_rabin);
        for (int p = sub_start; p <= sub_end; ++p) {
            rabin_slide(&sub_rabin, buf[p]);
            uint64_t v = sub_rabin.digest;

            // 插入到 top-K (这里 K=2 的手写快速实现)
            if (v < min1) {
                min2 = min1;
                min1 = v;
            } else if (v < min2) {
                min2 = v;
            }
        }

        // 如果子块长度小于 K（例如只有一个位置），把 min2 设为 min1 保证后续逻辑稳定
        if (min2 == std::numeric_limits<uint64_t>::max()) {
            min2 = min1;
        }

        // 4.2 将提取到的特征 (top-2 minima) 喂给 MinHash 计算器
        // 注意：原先是 {min_fp, max_fp}，现在改为 {min1, min2}
        uint64_t chunk_features[] = {min1, min2};

        for (uint64_t raw_feature : chunk_features) {
            for (int j = 0; j < total_features; j++) {
                // 线性变换
                uint64_t transformed = M2[j] * raw_feature + A2[j];
                // 更新全局最小值
                if (transformed < min_hash_values[j]) {
                    min_hash_values[j] = transformed;
                }
            }
        }
    }



    // 5. 将 MinHash 结果分组为 Super Features
     std::vector<uint64_t> super_features(sf_cnt_, 0);
     auto hash_buf = (const uint8_t *const)(min_hash_values.data());

     for (int i = 0; i < sf_cnt_; i++) {
         uint64_t group_hash = 0;
         auto this_group_buf = hash_buf + i * sf_subf_ * sizeof(uint64_t);
         for (int j = 0; j < sf_subf_ * sizeof(uint64_t); j++) {
             group_hash = (group_hash << 1) + GEAR_TABLE[this_group_buf[j]];
         }
         super_features[i] = group_hash;
     }

     return super_features;


    // 5.非聚合版 直接返回12个值
    // return min_hash_values;


}




// ================= CDFE 主逻辑 (Gear-first + Rabin fallback) =================
/*
Feature CDFEFeature::operator()(std::shared_ptr<Chunk> chunk) {
    int len = chunk->len();
    uint8_t* buf = chunk->buf();

    std::vector<int> breakpoint_list;
    breakpoint_list.push_back(0);

    // 1. CDFE 子块切分参数初始化
    int last_bp = 0;
    int curr_min = last_bp + L1_;
    int curr_max = last_bp + L2_;
    int curr_avg = last_bp + a_;

    // =========================
    // 2. CDFE 切分主循环（Gear-first）
    // =========================
    while (curr_max < len - 1) {
        int bp = -1;

        int seg_start = last_bp;
        int seg_end   = std::min(len - 1, curr_max);
        int local_len = seg_end - seg_start + 1;

        // --- 局部 Rabin & Gear rolling 指纹 ---
        std::vector<uint64_t> local_fps(local_len);
        std::vector<uint64_t> local_gear(local_len);

        rabin_t local_rabin;
        rabin_init(&local_rabin);
        uint64_t gear_fp = 0;

        for (int p = seg_start; p <= seg_end; ++p) {
            // Rabin（用于 fallback + 子块特征）
            rabin_slide(&local_rabin, buf[p]);
            local_fps[p - seg_start] = local_rabin.digest;

            // Gear（用于首选切点判定）
            gear_fp = (gear_fp << 1) + GEAR_TABLE[buf[p]];
            local_gear[p - seg_start] = gear_fp;
        }

        // =========================
        // 2.1 Gear FIRST（Primary）
        // =========================
        //const uint64_t gear_mask = default_odess_mask; // (1<<7)-1
        const uint64_t gear_mask = (1<<6)-1;
        bp = get_breakpoint_gear(local_gear,
                                 seg_start,
                                 curr_min,
                                 curr_max,
                                 curr_avg,
                                 gear_mask);

        if (bp != -1) {
            d1_cuts_++;   // Gear 视为 primary cut
        } else {
            // =========================
            // 2.2 Rabin D1 fallback
            // =========================
            bp = get_breakpoint(local_fps,
                                seg_start,
                                curr_min,
                                curr_max,
                                curr_avg,
                                D1_);
            if (bp != -1) {
                d1_cuts_++;
            } else {
                // =========================
                // 2.3 Rabin D2 fallback
                // =========================
                bp = get_breakpoint(local_fps,
                                    seg_start,
                                    curr_min,
                                    curr_max,
                                    curr_avg,
                                    D2_);
                if (bp != -1) {
                    d2_cuts_++;
                }
            }
        }

        // =========================
        // 2.4 强制切分
        // =========================
        if (bp == -1) {
            bp = curr_max;
            force_cuts_++;
        }

        breakpoint_list.push_back(bp);
        last_bp  = bp;
        curr_min = last_bp + L1_;
        curr_max = last_bp + L2_;
        curr_avg = last_bp + a_;
    }

    breakpoint_list.push_back(len - 1);
    total_sub_chunks_ += (breakpoint_list.size() - 1);

    // =========================
    // 3. MinHash 容器
    // =========================
    int total_features = sf_cnt_ * sf_subf_; // 12
    std::vector<uint64_t> min_hash_values(
        total_features,
        std::numeric_limits<uint64_t>::max()
    );

    // =========================
    // 4. 遍历子块，提取 top-2 minima 特征
    // =========================
    for (size_t i = 1; i < breakpoint_list.size(); ++i) {
        int sub_start = breakpoint_list[i - 1];
        int sub_end   = std::min(breakpoint_list[i], len - 1);

        uint64_t min1 = std::numeric_limits<uint64_t>::max();
        uint64_t min2 = std::numeric_limits<uint64_t>::max();

        rabin_t sub_rabin;
        rabin_init(&sub_rabin);

        for (int p = sub_start; p <= sub_end; ++p) {
            rabin_slide(&sub_rabin, buf[p]);
            uint64_t v = sub_rabin.digest;

            if (v < min1) {
                min2 = min1;
                min1 = v;
            } else if (v < min2) {
                min2 = v;
            }
        }

        if (min2 == std::numeric_limits<uint64_t>::max()) {
            min2 = min1;
        }

        uint64_t chunk_features[] = { min1, min2 };

        for (uint64_t raw_feature : chunk_features) {
            for (int j = 0; j < total_features; j++) {
                uint64_t transformed = M2[j] * raw_feature + A2[j];
                if (transformed < min_hash_values[j]) {
                    min_hash_values[j] = transformed;
                }
            }
        }
    }
*/
    // =========================
    // 5. 分组为 Super Features
    // =========================
    /*
    std::vector<uint64_t> super_features(sf_cnt_, 0);
    auto hash_buf = (const uint8_t* const)(min_hash_values.data());

    for (int i = 0; i < sf_cnt_; i++) {
        uint64_t group_hash = 0;
        auto this_group_buf = hash_buf + i * sf_subf_ * sizeof(uint64_t);
        for (int j = 0; j < sf_subf_ * sizeof(uint64_t); j++) {
            group_hash = (group_hash << 1) + GEAR_TABLE[this_group_buf[j]];
        }
        super_features[i] = group_hash;
    }

    return super_features;*/
                    
//    return min_hash_values;
//}



} // namespace Delta