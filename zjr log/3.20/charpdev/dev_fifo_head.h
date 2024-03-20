#ifndef _DEV_FIFO_HEAD_H
#define _DEV_FIFO_HEAD_H
#define DEV_FIFO_TYPE 'k'
// 定义一个没有数据传递的命令
#define DEV_FIFO_CLEAN _IO(DEV_FIFO_TYPE,0x10)
// 定义一个从设备读取数据的IO cmd
#define DEV_FIFO_GETVALUE _IOR(DEV_FIFO_TYPE,0x11,int)
// 定义一个向设备写数据的IO cmd
#define DEV_FIFO_SETVALUE _IOW(DEV_FIFO_TYPE,0x12,int)
#endif