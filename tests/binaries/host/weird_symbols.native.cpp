#include <compare>
#include <coroutine>
#include <cstdarg>
#include <cstddef>
#include <new>
#include <unistd.h>

void break_here(long long) {}

struct Point {
  long x, y;
};

union Bits {
  long l;
  char c[8];
};

enum Color {
  RED,
  GREEN = 0x8888
};

using Length = long;

int global_int = 0x1111;
Point global_struct = {0x2222, 0x3333};
Bits global_union = {0x7777};
Color global_enum = GREEN;
Length global_typedef = 0x9999;
int* global_pointer = &global_int;
bool global_bool = true;

namespace {
int table[4] = {1, 2, 3, 4};
int anon_int = 0x4444;
Point anon_struct = {0x5555, 0x6666};

int hidden(int i) {
  return table[i & 3];
}
} // namespace

namespace outer::inner {
struct Vec {
  int x, y;

  Vec operator+(Vec const& o) const {
    return {x + o.x, y + o.y};
  }

  Vec operator/(int d) const {
    return {x / d, y / d};
  }

  Vec& operator++() {
    ++x;
    return *this;
  }

  int operator[](int i) const {
    return i ? y : x;
  }

  int operator()(int a, int b) const {
    return a * x + b * y;
  }

  auto operator<=>(Vec const&) const = default;

  static void* operator new[](std::size_t n) {
    return ::operator new(n);
  }

  static void operator delete[](void* p) {
    ::operator delete(p);
  }
};

template <typename T> bool operator<(Vec const& v, T n) {
  return v.x < n;
}

struct Shape {
  virtual ~Shape() = default;
  virtual int area() const {
    return 0;
  }
};

struct Named {
  virtual ~Named() = default;
  virtual int id() const {
    return 0;
  }
};

struct Square : Shape, Named {
  int side = 3;
  int area() const override {
    return side * side;
  }
  int id() const override {
    return 4;
  }
};
} // namespace outer::inner

int sum(int n, ...) {
  va_list ap;
  va_start(ap, n);
  int total = 0;
  for (int i = 0; i < n; i++)
    total += va_arg(ap, int);
  va_end(ap);
  return total;
}

__attribute__((abi_tag("v2"))) int tagged() {
  return 2;
}

int bump(int by) {
  static int counter;
  counter += by;
  return counter;
}

template <typename T, int N> T first(T (&arr)[N]) {
  return arr[0];
}

int call_with(int (*fn)(int), int arg) {
  return fn(arg);
}

unsigned long long operator""_km(unsigned long long v) {
  return v * 1000;
}

inline int apply_twice(int v) {
  auto twice = [](int x) {
    return x * 2;
  };
  return call_with(twice, twice(v));
}

// clang names lambdas in non-inline functions $_N
int triple(int v) {
  auto thrice = [](int x) {
    return x * 3;
  };
  return thrice(v);
}

namespace kitchen {
struct Task {
  struct promise_type {
    Task get_return_object() {
      return Task{std::coroutine_handle<promise_type>::from_promise(*this)};
    }
    std::suspend_always initial_suspend() noexcept {
      return {};
    }
    std::suspend_always final_suspend() noexcept {
      return {};
    }
    void return_void() {}
    void unhandled_exception() {}
  };

  std::coroutine_handle<promise_type> handle;

  ~Task() {
    handle.destroy();
  }
};

struct Order {
  int id;
};

Task cook(Order order) {
  co_await std::suspend_always{};
  bump(order.id);
}
} // namespace kitchen

outer::inner::Vec gparam1{1, 2}, gparam2{3, 4};

int main() {
  int arr[3] = {7, 8, 9};

  outer::inner::Vec a{1, 2}, b{3, 4};
  outer::inner::Vec c = (a + b) / 2;
  ++c;
  bool less = (a <=> b) < 0 && a < 3;

  outer::inner::Vec* many = new outer::inner::Vec[2];
  delete[] many;

  outer::inner::Square sq;
  outer::inner::Shape* shape = &sq;
  outer::inner::Named* named = &sq;

  kitchen::Task task = kitchen::cook(kitchen::Order{7});
  task.handle.resume();
  task.handle.resume();

  getpid();

  long long total = hidden(1) + c[1] + c(1, 2) + sum(3, 1, 2, 3) + tagged() +
                    bump(5) + first(arr) + apply_twice(3) + shape->area() +
                    named->id() + 12_km + global_int + global_struct.x +
                    anon_int + anon_struct.x + triple(2) + less;
  break_here(total);

  return 0;
}
