#pragma once
#include <memory>
#include <variant>
#include <vector>
namespace Delta {
constexpr int default_finesse_sf_cnt = 3;
// every super feature is grouped with 4 sub-features by default
constexpr int default_finesse_sf_subf = 4;

constexpr int default_odess_sf_cnt = 3;
constexpr int default_odess_sf_subf = 4;
constexpr uint64_t default_odess_mask = (1 << 7) - 1;
class Chunk;
using Feature = std::variant<std::vector<std::vector<uint64_t>>,
                             std::vector<uint64_t>
                             >;

class FeatureCalculator {
public:
  // --- 新增这一行 ---
  virtual ~FeatureCalculator() = default;
  virtual Feature operator()(std::shared_ptr<Chunk> chunk) = 0;
};

class FinesseFeature : public FeatureCalculator {
public:
  FinesseFeature(const int sf_cnt = default_finesse_sf_cnt,
                 const int sf_subf = default_finesse_sf_subf)
      : sf_cnt_(sf_cnt), sf_subf_(sf_subf) {}

  Feature operator()(std::shared_ptr<Chunk> chunk) override;

private:
  // grouped super features count
  const int sf_cnt_;
  // how much sub feature does a one super feature contain
  const int sf_subf_;
};

class NTransformFeature : public FeatureCalculator {
public:
  NTransformFeature(const int sf_cnt = 3, const int sf_subf = 4)
      : sf_cnt_(sf_cnt), sf_subf_(sf_subf) {}

  Feature operator()(std::shared_ptr<Chunk> chunk) override;

private:
  // grouped super features count
  const int sf_cnt_;
  // how much sub feature does a one super feature contain
  const int sf_subf_;
};

class OdessFeature : public FeatureCalculator {
public:
  OdessFeature(const int sf_cnt = default_odess_sf_cnt,
               const int sf_subf = default_odess_sf_subf,
               const int mask = default_odess_mask)
      : sf_cnt_(sf_cnt), sf_subf_(sf_subf), mask_(mask) {}

  Feature operator()(std::shared_ptr<Chunk> chunk) override;

private:
  // grouped super features count
  const int sf_cnt_;
  // how much sub feature does a one super feature contain
  const int sf_subf_;

  const int mask_;
};

class OdessSubfeatures : public FeatureCalculator {
public:
  Feature operator()(std::shared_ptr<Chunk> chunk);
};

class PalantirFeature : public FeatureCalculator {
public:
  Feature operator()(std::shared_ptr<Chunk> chunk);
private:
  OdessSubfeatures get_sub_features_;
};



/*CDFE*/
class CDFEFeature : public FeatureCalculator {
public:
  // L1, L2, a, D1, D2: CDFE 切分参数
  // sf_cnt: 超级特征数量 (默认 3)
  // sf_subf: 每个超级特征包含的子特征数 (默认 4, 总共 12 次变换)
  CDFEFeature(int l1 = 32, int l2 = 128, int a = 64, int d1 = 56, int d2 = 12,
              int sf_cnt = 3, int sf_subf = 4)
      : L1_(l1), L2_(l2), a_(a), D1_(d1), D2_(d2), 
        sf_cnt_(sf_cnt), sf_subf_(sf_subf) {}

  // --- 新增：析构函数声明 ---
  ~CDFEFeature() override;

  Feature operator()(std::shared_ptr<Chunk> chunk) override;

private:
  // Algorithm 2: get_breakpoint
  int get_breakpoint(const std::vector<uint64_t>& fingerprints, 
                     int start_pos, int min_pos, int max_pos, int avg_pos, int divisor);
  // --- ADDED: Gear-based breakpoint search (uses gear_fps & mask) ---
  int get_breakpoint_gear(const std::vector<uint64_t>& gear_fps,
                          int start_pos, int min_pos, int max_pos, int avg_pos, uint64_t mask);
  const int L1_;
  const int L2_;
  const int a_;
  const int D1_;
  const int D2_;
  
  // N-Transform / MinHash 相关参数
  const int sf_cnt_;
  const int sf_subf_;

  // --- 新增：统计计数器 ---
  // 记录切分总数和各类切分的次数
  /***************************************/
  size_t total_sub_chunks_ = 0; 
  size_t d1_cuts_ = 0;          
  size_t d2_cuts_ = 0;          
  size_t force_cuts_ = 0;
  /***************************************/
};
} // namespace Delta