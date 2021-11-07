<template>
  <el-container>
    <el-aside>
      <navbar/>
    </el-aside>

    <el-container>
      <el-header>
        <breadcrumb/>
      </el-header>

      <el-main>
        <router-view/>
      </el-main>
    </el-container>

  </el-container>
</template>

<style>

@import url('https://fonts.googleapis.com/css2?family=Jost:ital,wght@0,300;0,400;0,500;0,700;1,500&display=swap');

html, body {
  margin: 0;
  overflow: hidden;
  min-height: 100% !important;
  height: 100%;
  font-family: 'Jost', Jost, Source Sans Pro, Helvetica Neue, Arial, sans-serif;
}

main {
  background-color: #f6f7f8;
}

aside {
  max-width: 60px;
  height: 100%;
  overflow: hidden;
}

header {
  height: 45px !important;
  background: rgba(15,23,42, 0.9);
  box-shadow: 0 0 5px rgba(0, 0, 0, 0.55);
  border-bottom: 3px solid transparent;
  border-image: repeating-linear-gradient(340.87deg, #777ce0 -5.97%, #60cefd 100.83%) 10;
}

.el-table__body-wrapper::-webkit-scrollbar {
  width: 20px;
}

.el-table__body-wrapper::-webkit-scrollbar-track {
  background-color: #F7F7F7;
  border-radius: 100px;
}

.el-table__body-wrapper::-webkit-scrollbar-thumb {
  border-radius: 100px;
  border: 5px solid transparent;
  background-clip: content-box;
  background-color: #60cefd;
}

</style>
<script>
import Navbar from "@/components/core/Navbar";
import Breadcrumb from "@/components/core/Breadcrumb";

export default {
  components: {Breadcrumb, Navbar}
}
</script>
