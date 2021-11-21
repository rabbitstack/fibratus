<template>
  <el-breadcrumb separator-class="el-icon-arrow-right">
    <el-row>
      <el-col>
        <el-breadcrumb-item><a href="/">Overview</a></el-breadcrumb-item>
        <el-breadcrumb-item v-for="(item, index) in crumbs" :key="index">{{ item.meta.text }}</el-breadcrumb-item>
      </el-col>
    </el-row>
  </el-breadcrumb>
</template>


<script>
export default {
  name: "Breadcrumb",
  data() {
    return {
      crumbs: []
    }
  },
  watch: {
    $route(route) {
      this.getCrumbs(route)
    }
  },
  methods: {
    getCrumbs(route) {
      if (route.matched) {
        this.crumbs = route.matched.filter(item => item.name)
      }
    }
  }
}
</script>

<style>
.el-breadcrumb {
  box-sizing: border-box;
  font-size: 15px !important;
  font-weight: 500;
  line-height: 2.4 !important;
}

.el-breadcrumb__inner {
  color: #fff !important;
}

.el-breadcrumb__inner a, .el-breadcrumb__inner.is-link {
  color: #fff !important;
}

.el-breadcrumb > ion-icon {
  position: relative;
  top: 22px;
}
</style>

