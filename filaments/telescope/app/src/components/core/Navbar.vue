<template>
  <el-menu class="nav-menu"
           background-color="#121F34"
           :default-active="$route.path"
           text-color="#fff"
           collapse
           router>
    <div class="logo">
    </div>
    <el-menu-item v-for="item in items" v-bind:key="item.route" v-bind:route="item.route" v-bind:index="item.route">
        <ion-icon v-bind:name="item.icon"></ion-icon>
        <template #title>{{ item.title }}</template>
    </el-menu-item>
  </el-menu>
</template>

<script>
import axios from 'axios'
import {ElMessage} from "element-plus";

export default {
  name: 'Navbar',
  data() {
    return {
      items: [],
    }
  },
  methods: {
    getItems() {
      axios.get('http://localhost:8081/navbar')
        .then((res) => {
          this.items = res.data
        })
        .catch((error) => {
          ElMessage.error({showClose: true, message: error, type: 'error'})
        })
    }
  },
  created() {
    this.getItems()
  }
}
</script>

<style>

.nav-menu {
  max-width: 100px;
  height: 100vh;
  overflow: hidden;
}

ul .el-menu-item {
  height: 40px;
  font-weight: 500;
  line-height: 38px;
  text-align: left;
}

li ion-icon {
  --ionicon-stroke-width: 40px;
  font-size: 20px;
  margin-right: 4px;
}

ul .el-menu-item.is-active {
  background: linear-gradient(340.87deg, #777ce0 -5.97%, #60cefd 100.83%);
  color: #fff;
  display: block;
}

.logo {
  height: 42px;
  background: linear-gradient(0deg, #0f172a 35%, #1b293d 75%);
  border-bottom: 3px solid transparent;
  border-image: repeating-linear-gradient(340.87deg, #777ce0 -5.97%, #60cefd 100.83%) 10;
}

.logo-text {
  color: #ffba00;
  font-size: 25px;
  align-content: center;
  top: 10px;
  right: 10px;
}
</style>
