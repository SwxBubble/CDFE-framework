#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "chunk/chunk.h"
#include "feature/features.h"

namespace fs = std::filesystem;
using Delta::Chunk;
using Delta::Feature;
using Delta::FeatureCalculator;
using Delta::FinesseFeature;
using Delta::NTransformFeature;
using Delta::OdessFeature;

struct Rec {
  std::string chunk_id;
  std::string split;
  std::string project;
  std::string version;
  uint64_t offset_start = 0;
  uint64_t chunk_order = 0;
  bool is_duplicate = false;
  bool is_dup_representative = false;
  std::string raw_chunk_path;
};

static std::string get_str_field(const std::string& line, const std::string& key) {
  std::string pat = "\"" + key + "\":\"";
  auto pos = line.find(pat);
  if (pos == std::string::npos) return "";
  pos += pat.size();
  auto end = line.find('"', pos);
  if (end == std::string::npos) return "";
  return line.substr(pos, end - pos);
}

static uint64_t get_u64_field(const std::string& line, const std::string& key) {
  std::string pat = "\"" + key + "\":";
  auto pos = line.find(pat);
  if (pos == std::string::npos) return 0;
  pos += pat.size();
  auto end = pos;
  while (end < line.size() && std::isdigit(static_cast<unsigned char>(line[end]))) end++;
  return std::stoull(line.substr(pos, end - pos));
}

static bool get_bool_field(const std::string& line, const std::string& key) {
  std::string pat_t = "\"" + key + "\":true";
  std::string pat_f = "\"" + key + "\":false";
  if (line.find(pat_t) != std::string::npos) return true;
  if (line.find(pat_f) != std::string::npos) return false;
  return false;
}

static std::string escape_json(const std::string& s) {
  std::ostringstream oss;
  for (char c : s) {
    switch (c) {
      case '\"': oss << "\\\""; break;
      case '\\': oss << "\\\\"; break;
      case '\n': oss << "\\n"; break;
      case '\r': oss << "\\r"; break;
      case '\t': oss << "\\t"; break;
      default: oss << c; break;
    }
  }
  return oss.str();
}

static std::vector<std::string> version_order(const std::string& project) {
  if (project == "linux") {
    return {
      "linux-3.0-rc1","linux-3.0-rc2","linux-3.0-rc3",
      "linux-3.0-rc4","linux-3.0-rc5","linux-3.0"
    };
  }
  if (project == "gcc") {
    return {
      "gcc-8.5.0","gcc-9.1.0","gcc-9.2.0","gcc-9.3.0","gcc-9.4.0",
      "gcc-10.1.0","gcc-10.2.0","gcc-10.3.0","gcc-11.1.0","gcc-11.2.0"
    };
  }
  return {};
}

static int version_index(const std::string& project, const std::string& version) {
  auto order = version_order(project);
  for (size_t i = 0; i < order.size(); ++i) {
    if (order[i] == version) return static_cast<int>(i);
  }
  return 1000000000;
}

static std::vector<Rec> load_manifest(const fs::path& manifest_path) {
  std::ifstream fin(manifest_path);
  if (!fin.is_open()) throw std::runtime_error("cannot open manifest");

  std::vector<Rec> out;
  std::string line;
  while (std::getline(fin, line)) {
    if (line.empty()) continue;
    Rec r;
    r.chunk_id = get_str_field(line, "chunk_id");
    r.split = get_str_field(line, "split");
    r.project = get_str_field(line, "project");
    r.version = get_str_field(line, "version");
    r.offset_start = get_u64_field(line, "offset_start");
    r.chunk_order = get_u64_field(line, "chunk_order");
    r.is_duplicate = get_bool_field(line, "is_duplicate");
    r.is_dup_representative = get_bool_field(line, "is_dup_representative");
    r.raw_chunk_path = get_str_field(line, "raw_chunk_path");
    if (!r.chunk_id.empty()) out.push_back(std::move(r));
  }
  return out;
}

static std::vector<uint64_t> compute_features(
    FeatureCalculator& calc,
    const std::string& path,
    uint32_t id) {
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) throw std::runtime_error("cannot open chunk file: " + path);

  in.seekg(0, std::ios::end);
  size_t sz = static_cast<size_t>(in.tellg());
  in.seekg(0, std::ios::beg);

  std::vector<uint8_t> buf(sz);
  in.read(reinterpret_cast<char*>(buf.data()), sz);

  auto chunk = Chunk::FromMemory(buf.data(), buf.size(), id);
  Feature f = calc(chunk);
  return std::get<std::vector<uint64_t>>(f);
}

static int shared_count(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
  std::set<uint64_t> sa(a.begin(), a.end());
  int cnt = 0;
  for (auto x : b) {
    if (sa.count(x)) cnt++;
  }
  return cnt;
}

struct Cand {
  const Rec* rec = nullptr;
  int score = 0;
  uint64_t offset_gap = 0;
};

int main(int argc, char** argv) {
  if (argc < 11) {
    std::cerr << "Usage: " << argv[0]
              << " --manifest <chunk_manifest_enriched.jsonl>"
              << " --out <candidate_pairs_*.jsonl>"
              << " --method <finesse|odess|ntransform>"
              << " --split <val|test|train>"
              << " --anchors <N>"
              << " --topk <K>\n";
    return 1;
  }

  std::string manifest_path, out_path, method, split;
  int anchor_n = 1000, topk = 5;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--manifest") manifest_path = argv[++i];
    else if (a == "--out") out_path = argv[++i];
    else if (a == "--method") method = argv[++i];
    else if (a == "--split") split = argv[++i];
    else if (a == "--anchors") anchor_n = std::stoi(argv[++i]);
    else if (a == "--topk") topk = std::stoi(argv[++i]);
  }

  auto all = load_manifest(manifest_path);

  std::unique_ptr<FeatureCalculator> calc;
  if (method == "finesse") calc = std::make_unique<FinesseFeature>();
  else if (method == "odess") calc = std::make_unique<OdessFeature>();
  else if (method == "ntransform") calc = std::make_unique<NTransformFeature>();
  else throw std::runtime_error("unknown method: " + method);

  std::vector<const Rec*> anchors;
  std::vector<const Rec*> refs;

  for (auto& r : all) {
    bool is_anchor = (r.split == split) && ((!r.is_duplicate) || r.is_dup_representative);
    if (is_anchor) anchors.push_back(&r);

    bool is_ref = false;
    if (split == "val") {
      is_ref = (r.split == "train");
    } else if (split == "test") {
      is_ref = (r.split == "train" || r.split == "val");
    } else if (split == "train") {
      is_ref = (r.split == "train");
    }
    if (is_ref) refs.push_back(&r);
  }

  std::mt19937 rng(2026);
  std::shuffle(anchors.begin(), anchors.end(), rng);
  if ((int)anchors.size() > anchor_n) anchors.resize(anchor_n);

  std::unordered_map<std::string, std::vector<uint64_t>> feat_cache;
  uint32_t cid = 1;

  for (auto* r : refs) {
    if (!feat_cache.count(r->chunk_id)) {
      feat_cache[r->chunk_id] = compute_features(*calc, r->raw_chunk_path, cid++);
    }
  }

  fs::create_directories(fs::path(out_path).parent_path());
  std::ofstream fout(out_path);
  if (!fout.is_open()) throw std::runtime_error("cannot open output");

  size_t written = 0;
  for (size_t i = 0; i < anchors.size(); ++i) {
    const Rec* a = anchors[i];
    auto a_feat = compute_features(*calc, a->raw_chunk_path, cid++);

    std::vector<Cand> cands;
    for (auto* r : refs) {
      if (r->project != a->project) continue;

      // 只允许历史版本
      if (version_index(r->project, r->version) >= version_index(a->project, a->version)) continue;

      int score = shared_count(a_feat, feat_cache[r->chunk_id]);
      if (score <= 0) continue;

      uint64_t gap = (a->offset_start > r->offset_start)
                   ? (a->offset_start - r->offset_start)
                   : (r->offset_start - a->offset_start);

      cands.push_back(Cand{r, score, gap});
    }

    std::sort(cands.begin(), cands.end(), [](const Cand& x, const Cand& y) {
      if (x.score != y.score) return x.score > y.score;
      return x.offset_gap < y.offset_gap;
    });

    if ((int)cands.size() > topk) cands.resize(topk);

    for (size_t rk = 0; rk < cands.size(); ++rk) {
      auto* b = cands[rk].rec;
      fout << "{"
           << "\"anchor_chunk_id\":\"" << escape_json(a->chunk_id) << "\","
           << "\"cand_chunk_id\":\"" << escape_json(b->chunk_id) << "\","
           << "\"method\":\"" << method << "\","
           << "\"rank\":" << (rk + 1) << ","
           << "\"raw_score\":" << cands[rk].score << ","
           << "\"matched_feature_count\":" << cands[rk].score << ","
           << "\"project\":\"" << escape_json(a->project) << "\","
           << "\"version_a\":\"" << escape_json(a->version) << "\","
           << "\"version_b\":\"" << escape_json(b->version) << "\""
           << "}\n";
      written++;
    }

    if ((i + 1) % 100 == 0) {
      std::cerr << "[progress] anchors " << (i + 1) << "/" << anchors.size()
                << ", written pairs=" << written << "\n";
    }
  }

  std::cerr << "[ok] method=" << method
            << ", anchors=" << anchors.size()
            << ", written pairs=" << written << "\n";
  return 0;
}